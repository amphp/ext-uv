<?php

function r($rs,$data)
{
    global $buf;
    global $x;
    $buf .= $data;
    if ($rs != 0) {
        echo "moe";
        uv_fs_read(uv_default_loop(),$x,"r");
    } else {
        var_dump($buf);
        uv_fs_close(uv_default_loop(), $x,function(){
        	echo "# closed\n";
        });
    }

}
uv_fs_open(uv_default_loop(),"./fs.php", 0, 0, function($r){
    global $x;
    $x = $r;
    uv_fs_read(uv_default_loop(),$r,"r");
});


uv_run();