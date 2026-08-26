package spice

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileTransferProgress represents the progress of a file transfer
type FileTransferProgress struct {
	FileName   string  // Name of the file being transferred
	TotalSize  int64   // Total file size in bytes
	BytesSent  int64   // Bytes sent so far
	Percentage float64 // Progress percentage (0-100)
	Status     uint32  // Current status (one of VD_AGENT_FILE_XFER_STATUS_*)
	Error      error   // Error if any
}

// FileTransferCallback is called when file transfer status changes
type FileTransferCallback func(progress FileTransferProgress)

// TransferDirection identifies whether an ActiveTransfer is host→guest
// (upload) or guest→host (download). The wire protocol uses the same
// message types in both directions; direction is a client-side notion.
type TransferDirection uint8

const (
	// TransferUpload is a host-to-guest transfer initiated by
	// SendFile. File is opened for reading; BytesSent counts bytes
	// sent to the guest.
	TransferUpload TransferDirection = 0
	// TransferDownload is a guest-to-host transfer initiated by
	// ReceiveFile. File is opened for writing; BytesSent counts
	// bytes written to disk. Named "BytesSent" for backward compat
	// with existing callers.
	TransferDownload TransferDirection = 1
)

// ActiveTransfer represents an active file transfer
type ActiveTransfer struct {
	ID           uint32               // Unique transfer ID
	Dir          TransferDirection    // Upload (host→guest) or Download (guest→host)
	File         *os.File             // File handle (read for upload, write for download)
	FileName     string               // File name (used in progress reporting)
	OriginalPath string               // Original path on the host
	TotalSize    int64                // Total file size — 0 when unknown (download without size hint)
	BytesSent    int64                // Bytes transferred so far
	Callback     FileTransferCallback // Progress callback
}

// SpiceWebdav handles the WebDAV channel communication for file transfers
type SpiceWebdav struct {
	cl            *Client
	conn          *SpiceConn
	transfers     map[uint32]*ActiveTransfer // Active transfers
	transfersLock sync.Mutex                 // Lock for the transfers map
	nextID        uint32                     // Next transfer ID
	idLock        sync.Mutex                 // Lock for the nextID
}

// setupWebdav creates and initializes the WebDAV channel
func (cl *Client) setupWebdav(id uint8) (*SpiceWebdav, error) {
	conn, err := cl.conn(ChannelWebdav, id, nil)
	if err != nil {
		return nil, err
	}
	m := &SpiceWebdav{
		cl:        cl,
		conn:      conn,
		transfers: make(map[uint32]*ActiveTransfer),
		nextID:    1,
	}
	conn.hndlr = m.handle

	go m.conn.ReadLoop()

	return m, nil
}

// getNextID returns the next available transfer ID
func (d *SpiceWebdav) getNextID() uint32 {
	d.idLock.Lock()
	defer d.idLock.Unlock()
	id := d.nextID
	d.nextID++
	return id
}

// handle processes incoming WebDAV channel messages
func (d *SpiceWebdav) handle(typ uint16, data []byte) {
	switch typ {
	case SPICE_WEBDAV_MSG_FILE_XFER_STATUS:
		d.handleFileXferStatus(data)
	case SPICE_WEBDAV_MSG_FILE_XFER_DATA:
		d.handleFileXferData(data)
	default:
		log.Printf("spice/webdav: got message type=%d", typ)
	}
}

// handleFileXferStatus processes a file transfer status message
func (d *SpiceWebdav) handleFileXferStatus(data []byte) {
	if len(data) < 8 {
		log.Printf("spice/webdav: invalid file transfer status message")
		return
	}

	id := binary.LittleEndian.Uint32(data[0:4])
	status := binary.LittleEndian.Uint32(data[4:8])

	d.transfersLock.Lock()
	transfer, ok := d.transfers[id]
	d.transfersLock.Unlock()

	if !ok {
		log.Printf("spice/webdav: received status for unknown transfer ID: %d", id)
		return
	}

	switch status {
	case VD_AGENT_FILE_XFER_STATUS_CAN_SEND_DATA:
		// Guest is ready to receive data, start sending
		d.sendNextChunk(transfer)
	case VD_AGENT_FILE_XFER_STATUS_SUCCESS:
		// Transfer completed successfully
		if transfer.Callback != nil {
			transfer.Callback(FileTransferProgress{
				FileName:   transfer.FileName,
				TotalSize:  transfer.TotalSize,
				BytesSent:  transfer.TotalSize,
				Percentage: 100.0,
				Status:     status,
			})
		}
		d.cleanupTransfer(id)
	case VD_AGENT_FILE_XFER_STATUS_CANCELLED, VD_AGENT_FILE_XFER_STATUS_ERROR,
		VD_AGENT_FILE_XFER_STATUS_NOT_ENOUGH_SPACE, VD_AGENT_FILE_XFER_STATUS_SESSION_LOCKED,
		VD_AGENT_FILE_XFER_STATUS_DISABLED:
		// Transfer failed
		var err error
		switch status {
		case VD_AGENT_FILE_XFER_STATUS_CANCELLED:
			err = fmt.Errorf("transfer cancelled by guest")
		case VD_AGENT_FILE_XFER_STATUS_ERROR:
			err = fmt.Errorf("transfer failed with error")
		case VD_AGENT_FILE_XFER_STATUS_NOT_ENOUGH_SPACE:
			err = fmt.Errorf("not enough space on guest")
		case VD_AGENT_FILE_XFER_STATUS_SESSION_LOCKED:
			err = fmt.Errorf("guest session is locked")
		case VD_AGENT_FILE_XFER_STATUS_DISABLED:
			err = fmt.Errorf("file transfers are disabled on guest")
		}

		if transfer.Callback != nil {
			transfer.Callback(FileTransferProgress{
				FileName:   transfer.FileName,
				TotalSize:  transfer.TotalSize,
				BytesSent:  transfer.BytesSent,
				Percentage: float64(transfer.BytesSent) * 100.0 / float64(transfer.TotalSize),
				Status:     status,
				Error:      err,
			})
		}
		d.cleanupTransfer(id)
	default:
		log.Printf("spice/webdav: unknown file transfer status: %d", status)
	}
}

// handleFileXferData processes a file transfer data chunk. Wire
// format: [uint32 id][uint32 size][size bytes payload]. A payload of
// size 0 marks end-of-transfer. Previously this method was a stub
// that silently dropped every guest→host byte. Downloads initiated
// via ReceiveFile now stream to the on-disk file the caller opened.
func (d *SpiceWebdav) handleFileXferData(data []byte) {
	if len(data) < 8 {
		log.Printf("spice/webdav: dropping short file-xfer data (%d bytes)", len(data))
		return
	}
	id := binary.LittleEndian.Uint32(data[:4])
	size := binary.LittleEndian.Uint32(data[4:8])
	// Guard against a hostile agent claiming a payload larger than
	// what actually arrived — the readloop already caps frames at
	// 10MB, but the declared size is server-supplied.
	if uint32(len(data)-8) < size {
		size = uint32(len(data) - 8)
	}
	payload := data[8 : 8+size]

	d.transfersLock.Lock()
	transfer, ok := d.transfers[id]
	d.transfersLock.Unlock()
	if !ok {
		log.Printf("spice/webdav: dropping data for unknown transfer id=%d", id)
		return
	}
	if transfer.Dir != TransferDownload || transfer.File == nil {
		log.Printf("spice/webdav: dropping data for non-download transfer id=%d", id)
		return
	}

	// Zero-size payload = end of transfer.
	if size == 0 {
		if transfer.Callback != nil {
			transfer.Callback(FileTransferProgress{
				FileName:   transfer.FileName,
				TotalSize:  transfer.TotalSize,
				BytesSent:  transfer.BytesSent,
				Percentage: 100.0,
				Status:     VD_AGENT_FILE_XFER_STATUS_SUCCESS,
			})
		}
		d.cleanupTransfer(id)
		return
	}

	if _, err := transfer.File.Write(payload); err != nil {
		log.Printf("spice/webdav: write to download file failed: %v", err)
		d.sendFileXferStatus(id, VD_AGENT_FILE_XFER_STATUS_ERROR)
		d.cleanupTransfer(id)
		return
	}
	transfer.BytesSent += int64(len(payload))

	if transfer.Callback != nil {
		pct := 0.0
		if transfer.TotalSize > 0 {
			pct = float64(transfer.BytesSent) * 100.0 / float64(transfer.TotalSize)
		}
		transfer.Callback(FileTransferProgress{
			FileName:   transfer.FileName,
			TotalSize:  transfer.TotalSize,
			BytesSent:  transfer.BytesSent,
			Percentage: pct,
			Status:     VD_AGENT_FILE_XFER_STATUS_CAN_SEND_DATA,
		})
	}
}

// ReceiveFile opens dstPath for writing and registers a transfer so
// incoming guest→host FILE_XFER_DATA messages get streamed to disk.
// The guest side initiates the transfer separately (via its own file-
// picker UI); this only prepares the receive slot.
//
// totalSize can be 0 when the guest hasn't sent a size hint yet; the
// callback's Percentage stays 0 until the transfer completes.
func (d *SpiceWebdav) ReceiveFile(id uint32, dstPath string, totalSize int64, cb FileTransferCallback) error {
	f, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", dstPath, err)
	}
	d.transfersLock.Lock()
	if _, exists := d.transfers[id]; exists {
		d.transfersLock.Unlock()
		_ = f.Close()
		return fmt.Errorf("transfer id %d already in flight", id)
	}
	d.transfers[id] = &ActiveTransfer{
		ID:           id,
		Dir:          TransferDownload,
		File:         f,
		FileName:     filepath.Base(dstPath),
		OriginalPath: dstPath,
		TotalSize:    totalSize,
		Callback:     cb,
	}
	d.transfersLock.Unlock()
	return nil
}

// cleanupTransfer removes a transfer from the active transfers map and closes the file
func (d *SpiceWebdav) cleanupTransfer(id uint32) {
	d.transfersLock.Lock()
	defer d.transfersLock.Unlock()

	transfer, ok := d.transfers[id]
	if !ok {
		return
	}

	if transfer.File != nil {
		transfer.File.Close()
	}

	delete(d.transfers, id)
}

// sendNextChunk sends the next chunk of data for a transfer
func (d *SpiceWebdav) sendNextChunk(transfer *ActiveTransfer) {
	// Read the next chunk of data from the file
	const chunkSize = 16 * 1024 // 16KB chunks
	buf := make([]byte, chunkSize)
	n, err := transfer.File.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("spice/webdav: error reading file: %v", err)
		d.sendFileXferStatus(transfer.ID, VD_AGENT_FILE_XFER_STATUS_ERROR)
		d.cleanupTransfer(transfer.ID)
		return
	}

	if n > 0 {
		// Send the data
		d.sendFileXferData(transfer.ID, buf[:n])
		transfer.BytesSent += int64(n)

		// Update progress
		if transfer.Callback != nil {
			transfer.Callback(FileTransferProgress{
				FileName:   transfer.FileName,
				TotalSize:  transfer.TotalSize,
				BytesSent:  transfer.BytesSent,
				Percentage: float64(transfer.BytesSent) * 100.0 / float64(transfer.TotalSize),
				Status:     VD_AGENT_FILE_XFER_STATUS_CAN_SEND_DATA,
			})
		}
	}

	// Check if we've reached the end of the file
	if err == io.EOF || n == 0 {
		// Send a zero-length data message to indicate end of transfer
		d.sendFileXferData(transfer.ID, []byte{})
	}
}

// sanitizeXferFileName strips newlines and carriage returns from a
// file name before it goes into the vdagent keyfile-shaped payload.
// Without this, a filename like "harmless\nname=evil\nsize=99" would
// inject arbitrary keys the guest agent parses — the receiver ends up
// writing to a path or with a size chosen by the sender. Also caps
// length so a hostile side can't force the agent to buffer megabytes.
func sanitizeXferFileName(name string) string {
	// Drop the classic control chars that end an INI line.
	repl := strings.NewReplacer(
		"\n", "_",
		"\r", "_",
		"\x00", "_",
	)
	out := repl.Replace(name)
	const maxNameLen = 255 // matches POSIX NAME_MAX and Windows MAX_PATH segment
	if len(out) > maxNameLen {
		out = out[:maxNameLen]
	}
	return out
}

// sendFileXferStart sends a file transfer start message
func (d *SpiceWebdav) sendFileXferStart(id uint32, fileName string, fileSize int64) error {
	// Build the file info data in the format expected by the agent
	// The format is a simple key-value format similar to INI files
	safeName := sanitizeXferFileName(fileName)
	keyFile := fmt.Sprintf("[vdagent-file-xfer]\nname=%s\nsize=%d\n", safeName, fileSize)

	// Create the message
	msgBuf := &bytes.Buffer{}
	binary.Write(msgBuf, binary.LittleEndian, id) // 4 bytes ID
	msgBuf.Write([]byte(keyFile))                 // File metadata

	return d.conn.WriteMessage(SPICE_WEBDAV_MSG_FILE_XFER_START, msgBuf.Bytes())
}

// sendFileXferData sends a chunk of file data
func (d *SpiceWebdav) sendFileXferData(id uint32, data []byte) error {
	// Create the message
	msgBuf := &bytes.Buffer{}
	binary.Write(msgBuf, binary.LittleEndian, id)                // 4 bytes ID
	binary.Write(msgBuf, binary.LittleEndian, uint32(len(data))) // 4 bytes size
	msgBuf.Write(data)                                           // File data

	return d.conn.WriteMessage(SPICE_WEBDAV_MSG_FILE_XFER_DATA, msgBuf.Bytes())
}

// sendFileXferStatus sends a file transfer status message
func (d *SpiceWebdav) sendFileXferStatus(id uint32, status uint32) error {
	// Create the message
	msgBuf := &bytes.Buffer{}
	binary.Write(msgBuf, binary.LittleEndian, id)     // 4 bytes ID
	binary.Write(msgBuf, binary.LittleEndian, status) // 4 bytes status

	return d.conn.WriteMessage(SPICE_WEBDAV_MSG_FILE_XFER_STATUS, msgBuf.Bytes())
}

// SendFile initiates a file transfer to the guest
func (d *SpiceWebdav) SendFile(filePath string, callback FileTransferCallback) (uint32, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open file: %w", err)
	}

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return 0, fmt.Errorf("failed to get file info: %w", err)
	}

	if fileInfo.IsDir() {
		file.Close()
		return 0, fmt.Errorf("cannot send directories: %s", filePath)
	}

	// Get a transfer ID
	id := d.getNextID()

	// Just use the base filename for transfer to guest
	fileName := filepath.Base(filePath)

	// Create a new transfer
	transfer := &ActiveTransfer{
		ID:           id,
		Dir:          TransferUpload,
		File:         file,
		FileName:     fileName,
		OriginalPath: filePath,
		TotalSize:    fileInfo.Size(),
		BytesSent:    0,
		Callback:     callback,
	}

	// Add to active transfers
	d.transfersLock.Lock()
	d.transfers[id] = transfer
	d.transfersLock.Unlock()

	// Send the start message
	err = d.sendFileXferStart(id, fileName, fileInfo.Size())
	if err != nil {
		d.cleanupTransfer(id)
		return 0, fmt.Errorf("failed to send file transfer start: %w", err)
	}

	return id, nil
}

// CancelTransfer cancels an active file transfer
func (d *SpiceWebdav) CancelTransfer(id uint32) error {
	d.transfersLock.Lock()
	_, ok := d.transfers[id]
	d.transfersLock.Unlock()

	if !ok {
		return fmt.Errorf("transfer ID not found: %d", id)
	}

	// Send a cancel status
	err := d.sendFileXferStatus(id, VD_AGENT_FILE_XFER_STATUS_CANCELLED)
	if err != nil {
		return fmt.Errorf("failed to send cancel status: %w", err)
	}

	// Clean up the transfer
	d.cleanupTransfer(id)
	return nil
}

// SendFiles sends multiple files to the guest
func (d *SpiceWebdav) SendFiles(filePaths []string, callback FileTransferCallback) ([]uint32, error) {
	ids := make([]uint32, 0, len(filePaths))
	errors := make([]error, 0)

	for _, path := range filePaths {
		id, err := d.SendFile(path, callback)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to send %s: %w", path, err))
			continue
		}
		ids = append(ids, id)
	}

	if len(errors) > 0 {
		// Combine all errors into one
		errMsg := strings.Builder{}
		errMsg.WriteString("failed to send some files: ")
		for i, err := range errors {
			if i > 0 {
				errMsg.WriteString("; ")
			}
			errMsg.WriteString(err.Error())
		}
		return ids, fmt.Errorf("%s", errMsg.String())
	}

	return ids, nil
}
