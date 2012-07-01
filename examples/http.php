<?php
/**
 * TODO: this implementation is not correct some error handling.
 */

function createServer(Closure $closure)
{
    $server = new HttpServer();
    $server->addListener($closure);

    return $server;
}

class HttpResponse
{
    protected $server;
    protected $client;

    protected $code = 200;
    protected $headers = array();
    protected $body = array();
    protected $http_version = "1.0";

    public function __construct($server, $client)
    {
        $this->server = $server;
        $this->client = $client;
    }

    public function writeHead($code, array $headers)
    {
        $this->code = $code;
        $this->headers = $headers;
    }

    public function write($data)
    {
        $this->body[] = $data;
    }

    public function end()
    {
        // Todo: implement correctly
        $buffer = "HTTP/1.0 200 OK\r\n";
        foreach ($this->headers as $key => $value) {
            $buffer .= $key . ": " . $value . "\r\n";
        }
        $buffer .= "\r\n";
        $buffer .= join("", $this->body);

        uv_write($this->client, $buffer, array($this->server, "onWrite"));
    }
}

class HttpServer
{
    protected $server;

    protected $clients = array();
    protected $parsers = array();
    protected $closure;

    public function __construct()
    {
        $this->server = uv_tcp_init();
    }

    public function addListener($closure)
    {
        $this->closure = $closure;
    }

    public function onShutdown($handle, $status)
    {
        uv_close($handle, array($this, "onClose"));
    }

    public function onClose($handle)
    {
        unset($this->clients[(int)$handle]);
        unset($this->parsers[(int)$handle]);

    }

    public function onWrite($client, $status)
    {
        if ($status == 0) {
            uv_shutdown($client, array($this, "onShutdown"));
        } else {
            echo "[write_failed]";
        }

    }

    public function onRead($client, $nread, $buffer)
    {
        //echo $buffer;
        //echo "--Error: " . uv_err_name(uv_last_error(uv_default_loop())) . PHP_EOL;

        if ($nread < 0) {
            //echo "[NREAD={$nread}]\n";
            uv_shutdown($client, array($this, "onShutdown"));
        } else if ($nread == 0) {
            // nothing to do.
            //echo "[NREAD=0]\n";
        } else {
            $result = array();

            if (uv_http_parser_execute($this->parsers[(int)($client)], $buffer, $result)){
                $response = new HttpResponse($this, $client);

                $closure = $this->closure;
                $closure($result, $response);
            } else {
                // nothing to do. (waiting next buffer)
            }
        }
    }

    public function onConnect($server, $status)
    {
        $client = uv_tcp_init();
        uv_tcp_nodelay($client, 1);
        uv_accept($server,$client);

        $this->clients[(int)$client]   = $client;
        $this->parsers[(int)($client)] = uv_http_parser_init();

        uv_read_start($client, array($this, "onRead"));
    }

    public function listen($port)
    {
        uv_tcp_nodelay($this->server, 1);
        uv_tcp_bind6($this->server, uv_ip6_addr("::1",$port));
        uv_listen($this->server, 511, array($this, "onConnect"));

        uv_run(uv_default_loop());
    }
}
