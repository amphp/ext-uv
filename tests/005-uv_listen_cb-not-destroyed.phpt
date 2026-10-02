--TEST--
Check for uv_listen callback is not destroyed by gc
--FILE--
<?php
class TcpServer
{
    private $loop;
    private $tcp;
    private $accepted = 0;

    public function __construct($loop)
    {
        $this->loop = $loop;
        $this->tcp = uv_tcp_init($loop);
    }

    public function bind(string $address, int $port)
    {
        uv_tcp_bind($this->tcp, uv_ip4_addr($address, $port));
    }

    public function listen()
    {
        uv_listen($this->tcp, 100, function ($server, $status) {

            $client = uv_tcp_init($this->loop);
            uv_accept($server, $client);

            uv_read_start($client, function ($socket, $buffer) {
                echo 'OK', PHP_EOL;
                uv_close($socket);
            });

            if (++$this->accepted === 4) {
                $this->close();
            }
        });
    }

    public function close()
    {
        if ($this->tcp instanceof UV) {
            uv_close($this->tcp);
        }
    }
}

$loop = uv_loop_new();

$tcpServer = new TcpServer($loop);
$tcpServer->bind('0.0.0.0', 9876);
$tcpServer->listen();

for ($i = 0; $i < 4; $i++) {
    $c = uv_tcp_init($loop);
    uv_tcp_connect($c, uv_ip4_addr('0.0.0.0', 9876), function ($stream, $stat) {
        uv_close($stream);
    });
}

uv_run($loop, UV::RUN_DEFAULT);

--EXPECTF--
OK
OK
OK
OK
