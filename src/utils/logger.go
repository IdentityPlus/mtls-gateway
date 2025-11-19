package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"identity.plus/mtls-gw/global"
)

var Log_Writer *DailyRotatingWriter

type DailyRotatingWriter struct {
	dir     string
	file    *os.File
	curDate string
	mu      sync.Mutex
}

func NewDailyRotatingWriter(dir string) (*DailyRotatingWriter, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	w := &DailyRotatingWriter{dir: dir}
	return w, w.rotateIfNeeded()
}

func (w *DailyRotatingWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.rotateIfNeeded(); err != nil {
		return 0, err
	}

	return w.file.Write(p)
}

func (w *DailyRotatingWriter) rotateIfNeeded() error {
	date := time.Now().Format("2006-01-02")

	if date == w.curDate && w.file != nil {
		return nil
	}

	if w.file != nil {
		w.file.Close()
	}

	filename := filepath.Join(w.dir, fmt.Sprintf("%s.log", date))
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	w.file = f
	w.curDate = date

	return nil
}

func (w *DailyRotatingWriter) Log_Eraser_Process() {
	time.Sleep(30 * time.Second)

	for {
		log.Printf("Cleaning up logs older than %v nonths.\n", global.Config__.Log_Retention)

		files, err := os.ReadDir(w.dir)
		if err != nil {
			log.Printf("error reading log dir: %w", err)
		}

		cutoff := time.Now().AddDate(0, -global.Config__.Log_Retention, 0)

		for _, fi := range files {
			if fi.IsDir() {
				continue
			}
			// Expecting file name format YYYY-MM-DD.log
			name := fi.Name()
			if len(name) != len("2006-01-02.log") || name[len(name)-4:] != ".log" {
				continue
			}

			t, err := time.Parse("2006-01-02", name[:10])
			if err != nil {
				continue
			}

			if t.Before(cutoff) {
				fullPath := filepath.Join(w.dir, name)
				if err := os.Remove(fullPath); err != nil {
					log.Printf("Warning: could not delete old log %s: %v\n", fullPath, err)
				}
			}
		}

		time.Sleep(2 * time.Hour)
	}
}

func (w *DailyRotatingWriter) Load(path string) string {
	data, error := os.ReadFile(w.dir + "/" + path)

	if error == nil {
		return string(data)
	} else {
		return "unable to load log file: " + error.Error()
	}
}

func (w *DailyRotatingWriter) Tail(path string, start int64) (string, int64) {
	fullPath := filepath.Join(w.dir, path)

	f, err := os.Open(fullPath)
	if err != nil {
		return "unable to open log file: " + err.Error(), 0
	}
	defer f.Close()

	// Get file size
	info, err := f.Stat()
	if err != nil {
		return "unable to stat file: " + err.Error(), 0
	}
	size := info.Size()

	// If start is beyond EOF, return empty & tell client new size
	if start == size {
		return "", size
	}

	if start > size {
		return "-1", size
	}

	// Seek to starting byte
	_, err = f.Seek(start, io.SeekStart)
	if err != nil {
		return "unable to seek: " + err.Error(), size
	}

	// Read the rest of the file
	data, err := io.ReadAll(f)
	if err != nil {
		return "unable to read: " + err.Error(), size
	}

	// Return (text, newEndOffset, error)
	return string(data), size
}

func (w *DailyRotatingWriter) Dir() string {
	return w.dir
}

func (w *DailyRotatingWriter) Delete(path string) string {

	if w.dir+"/"+path == w.file.Name() {
		log.Printf("Truncating log file %s per user request", w.file.Name())
		_ = os.Truncate(w.dir+"/"+path, 0)
		return "Will not delete current log file. Truncaing instead."
	}

	error := os.Remove(w.dir + "/" + path)

	if error != nil {
		log.Printf("Unable to delete file %s: %v, %s", w.dir+"/"+path, error, w.file.Name())
		return "Unable to delete file " + w.dir + "/" + path + ": " + error.Error()
	}

	return ""
}

func (w *DailyRotatingWriter) List() ([]string, error) {
	// Directory containing the files

	// Read all files in the directory
	files, err := os.ReadDir(w.dir)
	if err != nil {
		return nil, fmt.Errorf("error reading directory: %v", err)
	}

	// Array to store the resulting filenames
	var log_files []string

	// Loop over the files and process them
	for _, file := range files {
		// Get the filename
		filename := file.Name()

		// Check if the file ends with ".yam
		if filename != "_" {
			// Append to the result array
			log_files = append(log_files, filename)
		}
	}

	sort.Sort(sort.Reverse(sort.StringSlice(log_files)))

	return log_files, nil
}
