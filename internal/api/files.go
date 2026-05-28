package api

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/kilasos/kilasos/internal/audit"
	"github.com/kilasos/kilasos/internal/storage"
)

func safePath(path string) bool {
	if strings.Contains(path, "..") {
		return false
	}
	clean := filepath.Clean(path)
	if clean != "/mnt" && !strings.HasPrefix(clean, "/mnt/") {
		return false
	}
	return true
}

func ip(r *http.Request) string {
	if strings.Contains(r.RemoteAddr, ":") {
		host, _, _ := strings.Cut(r.RemoteAddr, ":")
		return host
	}
	return r.RemoteAddr
}

func fileListHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		path := r.URL.Query().Get("path")
		if path == "" {
			path = "/mnt"
		}
		if !safePath(path) {
			auditLog.Log("files", "FILE_LIST", "path traversal blocked: "+path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		nodes, err := p.FileList(r.Context(), path)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "FILE_LIST", "ok: "+path, ip(r), true)
		writeJSON(w, 200, nodes)
	}
}

func fileTreeHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		path := r.URL.Query().Get("path")
		if path == "" {
			path = "/mnt"
		}
		if !safePath(path) {
			auditLog.Log("files", "FILE_TREE", "path traversal blocked: "+path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		nodes, err := p.FileTree(r.Context(), path)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "FILE_TREE", "ok: "+path, ip(r), true)
		writeJSON(w, 200, nodes)
	}
}

func fileReadHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		path := r.URL.Query().Get("path")
		if !safePath(path) {
			auditLog.Log("files", "FILE_READ", "path traversal blocked: "+path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		content, err := p.FileRead(r.Context(), path)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "FILE_READ", "ok: "+path, ip(r), true)
		writeJSON(w, 200, map[string]string{"content": content})
	}
}

func filePreviewHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		path := r.URL.Query().Get("path")
		if !safePath(path) {
			auditLog.Log("files", "FILE_PREVIEW", "path traversal blocked: "+path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		preview, err := p.FilePreview(r.Context(), path)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "FILE_PREVIEW", "ok: "+path, ip(r), true)
		writeJSON(w, 200, preview)
	}
}

func fileUploadHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		path := r.FormValue("path")
		if path == "" {
			writeJSON(w, 400, map[string]string{"error": "path required"})
			return
		}
		if !safePath(path) {
			auditLog.Log("files", "FILE_UPLOAD", "path traversal blocked: "+path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		mr, err := r.MultipartReader()
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "not multipart"})
			return
		}
		var written int64
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			if part.FileName() == "" {
				continue
			}
			dst, err := os.Create(path)
			if err != nil {
				auditLog.Log("files", "FILE_UPLOAD", "create failed: "+err.Error(), ip(r), false)
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			written, err = io.Copy(dst, part)
			dst.Close()
			if err != nil {
				os.Remove(path)
				auditLog.Log("files", "FILE_UPLOAD", "write failed: "+err.Error(), ip(r), false)
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
		}
		auditLog.Log("files", "FILE_UPLOAD", fmt.Sprintf("ok: %s (%d bytes)", path, written), ip(r), true)
		writeJSON(w, 200, map[string]interface{}{"size": written})
	}
}

func fileDownloadHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		path := r.URL.Query().Get("path")
		if !safePath(path) {
			auditLog.Log("files", "FILE_DOWNLOAD", "path traversal blocked: "+path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		f, err := os.Open(path)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "file not found"})
			return
		}
		defer f.Close()
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(path))
		io.Copy(w, f)
		auditLog.Log("files", "FILE_DOWNLOAD", "ok: "+path, ip(r), true)
	}
}

func folderZipHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if !safePath(req.Path) {
			auditLog.Log("files", "FOLDER_ZIP", "path traversal blocked: "+req.Path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		resolved, err := filepath.EvalSymlinks(req.Path)
		if err != nil || !safePath(resolved) {
			auditLog.Log("files", "FOLDER_ZIP", "path traversal blocked (resolved): "+req.Path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		base := filepath.Base(resolved)
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename="+base+".zip")
		zw := zip.NewWriter(w)
		filepath.WalkDir(resolved, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			rel, _ := filepath.Rel(filepath.Dir(resolved), path)
			if d.IsDir() {
				zw.Create(rel + "/")
			} else {
				info, err := d.Info()
				if err != nil || info.Mode()&os.ModeSymlink != 0 {
					return nil
				}
				f, err := os.Open(path)
				if err != nil {
					return nil
				}
				defer f.Close()
				header, _ := zip.FileInfoHeader(info)
				header.Name = rel
				wr, _ := zw.CreateHeader(header)
				io.Copy(wr, f)
			}
			return nil
		})
		zw.Close()
		auditLog.Log("files", "FOLDER_ZIP", "ok: "+req.Path, ip(r), true)
	}
}

func fileRenameHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			OldPath string `json:"old_path"`
			NewPath string `json:"new_path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if !safePath(req.OldPath) || !safePath(req.NewPath) {
			auditLog.Log("files", "FILE_RENAME", "path traversal blocked", ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		if err := p.FileRename(r.Context(), req.OldPath, req.NewPath); err != nil {
			auditLog.Log("files", "FILE_RENAME", "fail: "+err.Error(), ip(r), false)
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "FILE_RENAME", fmt.Sprintf("ok: %s -> %s", req.OldPath, req.NewPath), ip(r), true)
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func fileCopyHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Src string `json:"src"`
			Dst string `json:"dst"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if !safePath(req.Src) || !safePath(req.Dst) {
			auditLog.Log("files", "FILE_COPY", "path traversal blocked", ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		if err := p.FileCopy(r.Context(), req.Src, req.Dst); err != nil {
			auditLog.Log("files", "FILE_COPY", "fail: "+err.Error(), ip(r), false)
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "FILE_COPY", fmt.Sprintf("ok: %s -> %s", req.Src, req.Dst), ip(r), true)
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func fileDeleteHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if !safePath(req.Path) {
			auditLog.Log("files", "FILE_DELETE", "path traversal blocked: "+req.Path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		if err := p.FileDelete(r.Context(), req.Path); err != nil {
			auditLog.Log("files", "FILE_DELETE", "fail: "+err.Error(), ip(r), false)
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "FILE_DELETE", "ok: "+req.Path, ip(r), true)
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func trashListHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		nodes, err := p.TrashList(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "TRASH_LIST", "ok", ip(r), true)
		writeJSON(w, 200, nodes)
	}
}

func trashRestoreHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			TrashPath string `json:"trash_path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if !safePath(req.TrashPath) {
			auditLog.Log("files", "TRASH_RESTORE", "path traversal blocked: "+req.TrashPath, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		if err := p.TrashRestore(r.Context(), req.TrashPath); err != nil {
			auditLog.Log("files", "TRASH_RESTORE", "fail: "+err.Error(), ip(r), false)
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "TRASH_RESTORE", "ok: "+req.TrashPath, ip(r), true)
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func trashEmptyHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		if err := p.TrashEmpty(r.Context()); err != nil {
			auditLog.Log("files", "TRASH_EMPTY", "fail: "+err.Error(), ip(r), false)
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "TRASH_EMPTY", "ok", ip(r), true)
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func fileChmodHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if !safePath(req.Path) {
			auditLog.Log("files", "FILE_CHMOD", "path traversal blocked: "+req.Path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		if err := p.FileChmod(r.Context(), req.Path, req.Mode); err != nil {
			auditLog.Log("files", "FILE_CHMOD", "fail: "+err.Error(), ip(r), false)
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "FILE_CHMOD", fmt.Sprintf("ok: %s %s", req.Path, req.Mode), ip(r), true)
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func fileChownHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Path string `json:"path"`
			Uid  int    `json:"uid"`
			Gid  int    `json:"gid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if !safePath(req.Path) {
			auditLog.Log("files", "FILE_CHOWN", "path traversal blocked: "+req.Path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		if err := p.FileChown(r.Context(), req.Path, req.Uid, req.Gid); err != nil {
			auditLog.Log("files", "FILE_CHOWN", "fail: "+err.Error(), ip(r), false)
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "FILE_CHOWN", fmt.Sprintf("ok: %s uid=%d gid=%d", req.Path, req.Uid, req.Gid), ip(r), true)
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func listSharesHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		shares, err := p.ListShareLinks(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "LIST_SHARES", "ok", ip(r), true)
		writeJSON(w, 200, shares)
	}
}

func createShareLinkHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Path      string `json:"path"`
			ExpiresIn int    `json:"expires_in"`
			MaxUses   int    `json:"max_uses"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if !safePath(req.Path) {
			auditLog.Log("files", "CREATE_SHARE", "path traversal blocked: "+req.Path, ip(r), false)
			writeJSON(w, 403, map[string]string{"error": "invalid path"})
			return
		}
		link, err := p.CreateShareLink(r.Context(), req.Path, storage.ShareLinkOptions{
			ExpiresIn: req.ExpiresIn,
			MaxUses:   req.MaxUses,
		})
		if err != nil {
			auditLog.Log("files", "CREATE_SHARE", "fail: "+err.Error(), ip(r), false)
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "CREATE_SHARE", "ok: "+req.Path, ip(r), true)
		writeJSON(w, 200, link)
	}
}

func revokeShareHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		id := filepath.Base(r.URL.Path)
		if id == "" {
			writeJSON(w, 400, map[string]string{"error": "id required"})
			return
		}
		if err := p.RevokeShareLink(r.Context(), id); err != nil {
			auditLog.Log("files", "REVOKE_SHARE", "fail: "+err.Error(), ip(r), false)
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "REVOKE_SHARE", "ok: "+id, ip(r), true)
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func getShareHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		id := filepath.Base(r.URL.Path)
		link, err := p.GetShareLink(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "GET_SHARE", "ok: "+id, ip(r), true)
		writeJSON(w, 200, link)
	}
}

func bulkDeleteHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Paths []string `json:"paths"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		for _, path := range req.Paths {
			if !safePath(path) {
				auditLog.Log("files", "BULK_DELETE", "path traversal blocked: "+path, ip(r), false)
				writeJSON(w, 403, map[string]string{"error": "invalid path: " + path})
				return
			}
		}
		if err := p.BulkDelete(r.Context(), req.Paths); err != nil {
			auditLog.Log("files", "BULK_DELETE", "fail: "+err.Error(), ip(r), false)
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "BULK_DELETE", fmt.Sprintf("ok: %d files", len(req.Paths)), ip(r), true)
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func bulkMoveHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Ops []storage.BulkMoveOp `json:"ops"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		for _, op := range req.Ops {
			if !safePath(op.Src) || !safePath(op.Dst) {
				auditLog.Log("files", "BULK_MOVE", "path traversal blocked", ip(r), false)
				writeJSON(w, 403, map[string]string{"error": "invalid path"})
				return
			}
		}
		if err := p.BulkMove(r.Context(), req.Ops); err != nil {
			auditLog.Log("files", "BULK_MOVE", "fail: "+err.Error(), ip(r), false)
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log("files", "BULK_MOVE", fmt.Sprintf("ok: %d ops", len(req.Ops)), ip(r), true)
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}