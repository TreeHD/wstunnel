// slaves.go — Master 端 Slave 節點註冊資料。
package store

import (
	"database/sql"
	"errors"
	"time"
)

// SlaveRecord 對應 cluster.SlaveRecord 在 store 層的副本。
// 之所以複製一份而不直接借用 config.SlaveRecord,是為了讓 store
// 不依賴上層 package(避免循環匯入)。cluster 端會自己做 mapping。
//
// JSON tags 是必要的:這個 struct 會直接在 admin API
// (POST /api/cluster/slaves)的 response 中序列化給前端使用,
// 前端讀的是 snake_case 欄位。
type SlaveRecord struct {
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name"`
	Token     string `json:"token"`
	Notes     string `json:"notes,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// ErrSlaveNotFound 指定節點不存在。
var ErrSlaveNotFound = errors.New("slave not found")

// UpsertSlave 建立或更新節點(token / name / notes)。
func UpsertSlave(s SlaveRecord) error {
	if s.CreatedAt == 0 {
		s.CreatedAt = time.Now().Unix()
	}
	_, err := db.Exec(`INSERT INTO slaves(node_id,node_name,token,notes,created_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET
			node_name=excluded.node_name,
			token=excluded.token,
			notes=excluded.notes`,
		s.NodeID, s.NodeName, s.Token, s.Notes, s.CreatedAt)
	return err
}

// GetSlave 依 NodeID 查單筆。
func GetSlave(nodeID string) (SlaveRecord, error) {
	var s SlaveRecord
	err := db.QueryRow(`SELECT node_id,node_name,token,notes,created_at FROM slaves WHERE node_id=?`, nodeID).
		Scan(&s.NodeID, &s.NodeName, &s.Token, &s.Notes, &s.CreatedAt)
	if err == sql.ErrNoRows {
		return SlaveRecord{}, ErrSlaveNotFound
	}
	return s, err
}

// ListSlaves 列出所有節點。
func ListSlaves() ([]SlaveRecord, error) {
	rows, err := db.Query(`SELECT node_id,node_name,token,notes,created_at FROM slaves ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SlaveRecord
	for rows.Next() {
		var s SlaveRecord
		if err := rows.Scan(&s.NodeID, &s.NodeName, &s.Token, &s.Notes, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// RenameSlave 更新節點顯示名稱。
func RenameSlave(nodeID, newName string) error {
	res, err := db.Exec(`UPDATE slaves SET node_name=? WHERE node_id=?`, newName, nodeID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrSlaveNotFound
	}
	return nil
}

// DeleteSlave 移除節點。
func DeleteSlave(nodeID string) error {
	_, err := db.Exec(`DELETE FROM slaves WHERE node_id=?`, nodeID)
	return err
}
