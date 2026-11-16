package proxy

import (
	"encoding/json"
	"errors"

	"github.com/nomaskscientist/ifcproxy/internal/taint"
)

// MCP Tasks (spec 2025-11-25, experimental): a task-augmented tools/call is
// answered with a CreateTaskResult that carries only a taskId; the tool's
// output arrives later in the response to tasks/result, and task metadata
// (statusMessage) in tasks/get, tasks/cancel and tasks/list responses.
//
// The tools/call itself is decided like any other call, and its
// CreateTaskResult taints the session with the tool's labels (so within one
// session the later content is already covered). On top of that the proxy
// remembers taskId -> labels, so that task responses for tasks it did not
// see created here (created before a restart, by another session, or a
// guessed id) fail closed: they carry every known label.

// maxTasks bounds the task table. Tasks created after it is full are not
// remembered; looking them up later fails closed.
const maxTasks = 4096

type pendingKind uint8

const (
	kindPlain    pendingKind = iota // non-tool request: response not labelled
	kindToolCall                    // tools/call: response carries the tool's labels
	kindTaskCall                    // task-augmented tools/call: also record the taskId
	kindTaskList                    // tasks/list: labels depend on the listed taskIds
)

// taskLabels returns the labels for a response about taskID.
func (p *Proxy) taskLabels(taskID string) taint.Label {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l, ok := p.tasks[taskID]; ok {
		return l
	}
	return taint.Known
}

// isTaskMethod reports whether method is one of the tasks/* requests.
func isTaskMethod(method string) bool {
	switch method {
	case "tasks/result", "tasks/get", "tasks/cancel", "tasks/list":
		return true
	}
	return false
}

// taskRequest returns the pending entry for a client request on a tasks/*
// method. Ambiguous params (duplicate or case-variant "taskId", a non-string
// taskId) are rejected: a lenient server could read a different task than
// the proxy. A missing taskId fails closed (every label).
func (p *Proxy) taskRequest(method string, params json.RawMessage) (pending, error) {
	if method == "tasks/list" {
		return pending{kind: kindTaskList, name: method}, nil
	}
	l := taint.Known
	if len(params) > 0 && params[0] == '{' {
		var id string
		found := false
		err := walkObject(params, func(k string, v json.RawMessage) error {
			if k == "taskId" {
				if len(v) == 0 || v[0] != '"' || json.Unmarshal(v, &id) != nil {
					return &rpcError{codeInvalidParams, "taskId must be a string"}
				}
				found = true
			}
			return nil
		}, []string{"taskId"})
		if err != nil {
			var re *rpcError
			if errors.As(err, &re) && re.code == codeInvalidRequest {
				re.code = codeInvalidParams
			}
			return pending{}, err
		}
		if found {
			l = p.taskLabels(id)
		}
	}
	return pending{kind: kindToolCall, name: method, produces: l}, nil
}

// recordTask remembers the taskId from a CreateTaskResult. A response that
// does not contain one (e.g. the server ran the call synchronously, or
// returned an error) is ignored: labels were already applied.
func (p *Proxy) recordTask(result json.RawMessage, l taint.Label) {
	var r struct {
		Task struct {
			TaskID string `json:"taskId"`
		} `json:"task"`
	}
	if json.Unmarshal(result, &r) != nil || r.Task.TaskID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if prev, ok := p.tasks[r.Task.TaskID]; ok {
		p.tasks[r.Task.TaskID] = prev | l
		return
	}
	if len(p.tasks) < maxTasks {
		p.tasks[r.Task.TaskID] = l
	}
}

// listLabels returns the labels of a tasks/list result: the union of the
// labels of the listed tasks, or every label if any listed task is unknown
// or the result cannot be read.
func (p *Proxy) listLabels(result json.RawMessage) taint.Label {
	var r struct {
		Tasks []struct {
			TaskID string `json:"taskId"`
		} `json:"tasks"`
	}
	if json.Unmarshal(result, &r) != nil {
		return taint.Known
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var l taint.Label
	for _, t := range r.Tasks {
		tl, ok := p.tasks[t.TaskID]
		if !ok {
			return taint.Known
		}
		l |= tl
	}
	return l
}
