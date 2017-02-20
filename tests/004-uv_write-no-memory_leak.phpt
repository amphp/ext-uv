--TEST--
Check for uv_write has no memory leak
--FILE--
<?php
class TestCase {
    public $counter = 0;

    public function run() {
        $loop = uv_loop_new();

        $handler = uv_pipe_init($loop, false);
        uv_pipe_open($handler, (int) STDOUT);

        $a = 0;

        while (++$a <= 1000) {
            uv_write($handler, '', function() {
                $this->counter++;
            });
        }

        uv_run($loop, \UV::RUN_DEFAULT);
        uv_close($handler);
    }
}

$t = new TestCase;
$memory = memory_get_usage();

$t->run();
echo $t->counter, PHP_EOL;
unset($t);

echo memory_get_usage() - $memory, PHP_EOL;
--EXPECTF--
1000
0