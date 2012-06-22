<?php

uv_fs_open(uv_default_loop(),"./tmp", UV::O_WRONLY,
    UV::S_IRWXU | UV::S_IRUSR,
    function($r){
	var_dump($r);
    uv_fs_ftruncate(uv_default_loop(),$r,0, function() use ($r){
        uv_fs_close(uv_default_loop(),$r,function(){});
    });
});


uv_run();
