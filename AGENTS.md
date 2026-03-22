## socks5 客户端 & 服务端实现问题记录（2026-02-27）

- **整体协议覆盖不足（当前状态：仅支持 CONNECT + IPv4/FQDN，IPv6/BIND/UDP 明确不支持）**
  - 只实现了 SOCKS5 的 CONNECT，BIND / UDP ASSOCIATE 目前仍未实现，遇到非 CONNECT 会返回错误，属于「明确不支持」而非静默失败。
  - 服务器端仅支持 IPv4 和域名，IPv6 仍旧返回错误，但已在代码中通过错误信息与 `net.JoinHostPort` 组合形式更明确地区分支持范围。

- **认证逻辑与配置不匹配（已部分修复）**
  - 服务端：`authenticate` 现在会根据 `Server.Auth.Method` 选择认证方式，目前正式支持 `none`（无认证），其他方法会返回 `NO ACCEPTABLE METHODS` 并记录错误，避免静默接受未实现的认证方式。
  - 客户端：仍然只真正支持 `NO_AUTH`，后续如果引入用户名/密码等方式，需要同时扩展客户端 `authenticate`。当前版本的官方支持矩阵为：`method = "none"`。

- **连接建立与响应解析存在协议兼容性问题**
  - 服务端 `connect` 只校验 `VER`、`CMD`，对 `RSV` 和非法组合缺乏更严格校验。
  - 服务器响应固定写 `VER=0x05, REP=0x00, RSV=0x00, ATYP=0x01, BND.ADDR=0.0.0.0, BND.PORT=0`，但客户端 `connect` 只读取前 2 字节（`VER`、`REP`），忽略后续 `ATYP/BND.ADDR/BND.PORT`，导致这 8 个字节残留在 client/server 通道中，后续业务数据读取会先读到这些“脏数据”，对上层协议（尤其是 HTTP 文本协议）来说是实质性的兼容性 bug。

- **转发与连接生命周期管理存在隐患**
  - 服务端 `forward` 使用两个 goroutine 做双向 `io.Copy`，但没有超时、限流、最大连接数等保护，易被长连接或慢连接拖垮。
  - 连接关闭依赖 `io.Copy` 返回后 `cancel()`，设计上简单但对异常半关闭、RST 等情况缺乏精细处理。

- **Client.Connect 的读取循环设计有隐患**
  - `Connect` 中的缓冲策略：
    - 初始化 `b := make([]byte, 0, 512)`，在 `len(b) == cap(b)` 时通过 `append` 人为扩容再 `Read`，虽然从语义上可以工作，但写法非常绕，可读性和可维护性都比较差。
  - 在错误（包括 `EOF`）时只返回 `b, err`，但不负责关闭连接，也没有重连/重认证策略，长时间复用同一底层连接可能留下一堆异常状态。

- **客户端职责与 CLI 形态有限**
  - 当前 `Client` 更像是「一次性请求工具」，`Connect` 内部串行执行：建 TCP -> SOCKS 认证 -> SOCKS CONNECT -> 发送数据 -> 读完为止，无法很好支持长连接协议（如 WebSocket）或流式场景。
  - CLI demo 只适合 `echo HTTP 请求 | client` 的一次性场景，对真实浏览器/系统代理场景不适用。

- **其他小问题与可改进点**
  - 服务器的 `Run` 方法内部重新声明了一个 `tcpServer := tcp.Server{}`，而不是使用 `Server` 中嵌入的 `tcp.Server` 字段，可能导致配置不一致或无法复用已有配置。
  - 错误日志和返回信息较为粗糙（例如 `invalid ver`/`invalid cmd`），后续排查复杂问题时可读性一般。
  - 协议注释较多，但与实际实现之间有部分脱节（例如 BIND/UDP/认证方式），容易给后续维护者造成「已经实现」的错觉。

> 后续如果要稳定对外提供 socks5 服务，需要：
> 1）补齐协议特性（至少明确支持范围并在代码中体现），2）梳理客户端读写循环与连接生命周期，3）把 `Auth` 配置真正落地到握手逻辑中。

---

## 测试用例（2026-02-27）

- **server_test.go**：覆盖服务端逻辑
  - `authenticate`：无认证成功、非法版本、不支持的 method（credentials）、客户端未提供 NO_AUTH 时返回 0xFF。
  - `connect`：IPv4/域名成功（含 OnConn）、IPv6 明确不支持、非法 CMD/VER/ATYP、OnConn 返回错误。
  - `forward`：双向转发（client→target、target→client）。
  - `process`：完整流程（auth + CONNECT + 转发到 echo 服务，验证回显）。
  - `Run`：无效地址时返回错误（避免测试中启动永不返回的 accept 循环）。
- **client_test.go**：覆盖客户端逻辑
  - `authenticate`：成功、服务端返回错误版本/不支持的 method。
  - `connect`：服务端返回 IPv4/FQDN/IPv6 类型 BND 时正确消费完整响应、rep≠0 时返回错误。
  - `Connect`：完整流程（dial + auth + connect + 写数据 + 读至 EOF），验证无协议残留字节、EOF 后 conn 置 nil、dial 失败时返回错误。
- **constants_test.go**：校验协议常量（Version5、Auth*、Cmd*、AddrType*）与 RFC 一致。
- **proxy_realworld_test.go**：real world 代理集成测试
  - 启动 `httptest` 目标 HTTP 服务 + 测试专用 socks5 accept loop。
  - 使用 `net/http` 自定义 `DialContext` 通过 socks5 握手代理访问目标，验证能正确拿到 HTTP 响应体（同时验证无 SOCKS 握手/CONNECT 残留字节污染）。

运行：`go test -v ./...`

