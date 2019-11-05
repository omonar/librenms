<?php
require 'includes/html/graphs/common.inc.php';

$colours       = 'mixed';
$unit_text     = 'Bits/s';
$unitlen       = 10;
$bigdescrlen   = 10;
$smalldescrlen = 10;
$dostack       = 0;
$printtotal    = 0;
$addarea       = 1;
$transparency  = 15;

$rrd_filename = rrd_name($device['hostname'], array('app', $app['app_type'], $app['app_id']));

if (rrdtool_check_rrd_exists($rrd_filename)) {
    $rrd_list = array(
        array(
            'filename' => $rrd_filename,
            'descr'    => 'Video',
            'ds'       => 'total_bitrate_video',
            'colour'   => '90B040',
        ),
        array(
            'filename' => $rrd_filename,
            'descr'    => 'Audio',
            'ds'       => 'total_bitrate_audio',
            'colour'   => '8080C0',
            'invert'   => true,
        ),
    );
} else {
    echo "file missing: $rrd_filename";
}

require 'includes/html/graphs/generic_multi.inc.php';
