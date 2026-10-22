<?php
var_dump(ini_get('memory_hard_limit_percent'));
echo 'upload_progress.enabled=';
var_dump(ini_get('session.upload_progress.enabled'));
echo PHP_VERSION, " / ", PHP_SAPI, "\n";
