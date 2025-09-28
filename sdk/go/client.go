package vivified

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
)

type VivifiedClient struct {
    baseURL string
    token   string
    httpc   *http.Client
}

func NewClient(baseURL string, token string) *VivifiedClient {
    if baseURL == "" {
        if v := os.Getenv("VIVIFIED_BASE_URL"); v != "" {
            baseURL = v
        } else {
            baseURL = "http://localhost:8000"
        }
    }
    if token == "" {
        token = os.Getenv("VIVIFIED_TOKEN")
    }
    return &VivifiedClient{baseURL: baseURL, token: token, httpc: &http.Client{}}
}

func (c *VivifiedClient) doJSON(method, path string, body any, out any) error {
    var buf *bytes.Buffer
    if body != nil {
        b, err := json.Marshal(body)
        if err != nil {
            return err
        }
        buf = bytes.NewBuffer(b)
    } else {
        buf = bytes.NewBuffer(nil)
    }
    req, err := http.NewRequest(method, c.baseURL+path, buf)
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")
    if c.token != "" {
        req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
    }
    resp, err := c.httpc.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return fmt.Errorf("request failed: %s", resp.Status)
    }
    if out != nil {
        return json.NewDecoder(resp.Body).Decode(out)
    }
    return nil
}

func (c *VivifiedClient) PublishEvent(eventType string, payload map[string]any, sourcePlugin string, dataTraits []string) (map[string]any, error) {
    body := map[string]any{
        "event_type":    eventType,
        "payload":       payload,
        "source_plugin": sourcePlugin,
        "data_traits":   dataTraits,
    }
    var out map[string]any
    err := c.doJSON(http.MethodPost, "/messaging/events", body, &out)
    return out, err
}

// Subscribe placeholder for parity
func (c *VivifiedClient) Subscribe(_eventType string, _handler func(map[string]any)) error { return nil }

func (c *VivifiedClient) CallPlugin(targetPlugin, operation string, payload map[string]any) (map[string]any, error) {
    var out map[string]any
    err := c.doJSON(http.MethodPost, "/gateway/"+targetPlugin+"/"+operation, payload, &out)
    return out, err
}

func (c *VivifiedClient) CallExternal(pluginID, url, method string, headers map[string]string, body map[string]any) (map[string]any, error) {
    req := map[string]any{"plugin_id": pluginID, "url": url, "method": method, "headers": headers, "body": body}
    var out map[string]any
    err := c.doJSON(http.MethodPost, "/gateway/proxy", req, &out)
    return out, err
}

func (c *VivifiedClient) GetConfig() (map[string]any, error) {
    var out map[string]any
    err := c.doJSON(http.MethodGet, "/admin/config", nil, &out)
    return out, err
}

func (c *VivifiedClient) SetConfig(key string, value any, isSensitive bool, reason string) (map[string]any, error) {
    body := map[string]any{"key": key, "value": value, "is_sensitive": isSensitive, "reason": reason}
    var out map[string]any
    err := c.doJSON(http.MethodPut, "/admin/config", body, &out)
    return out, err
}

