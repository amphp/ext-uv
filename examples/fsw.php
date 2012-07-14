<?php

uv_fs_open(uv_default_loop(),"./tmp", UV::O_WRONLY | UV::O_CREAT | UV::O_APPEND,
    UV::S_IRWXU | UV::S_IRUSR,
    function($r){
	var_dump($r);
    uv_fs_write(uv_default_loop(),$r,"hello",0, function($a) use ($r){
    	var_dump($a);
    	var_dump("ok");
        uv_fs_fdatasync(uv_default_loop(),$r,function(){
            echo "fsync finished";
        });
    });
});


uv_run();
