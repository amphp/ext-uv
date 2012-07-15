<?php
$base = dirname(dirname(__FILE__));
$sources = array("php_uv.c","uv.c");

foreach($sources as $source) {
    $data = file_get_contents($base . DIRECTORY_SEPARATOR . $source);
    if (preg_match_all("/{{{ proto\s(.+?)\*\//s", $data, $matches)) {
        foreach($matches[1] as $proto) {
            printf("### %s\n\n",$proto);
        }
    }
}
