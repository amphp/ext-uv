<?php

uv_fs_open(uv_default_loop(),"./tmp", 521, 0, function($r){
	var_dump($r);
    uv_fs_write(uv_default_loop(),$r,"hello",function($a){
    	var_dump($a);
    	var_dump("ok");
    });
});


uv_run();
