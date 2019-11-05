<?php

$graphs = array(
    'hls_multi_video' => 'Total',
);

foreach ($graphs as $key => $text) {
    $graph_type            = $key;
    $graph_array['height'] = '100';
    $graph_array['width']  = '215';
    $graph_array['to'] = \LibreNMS\Config::get('time.now');
    $graph_array['id']     = $app['app_id'];
    $graph_array['type']   = 'application_'.$key;

    echo '<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">'.$text.'</h3>
    </div>
    <div class="panel-body">
    <div class="row">';
    include 'includes/html/print-graphrow.inc.php';
    echo '</div>';
    echo '</div>';
    echo '</div>';
}

$options = array(
    'filter' => array(
        'type' => array('=', 'hls'),
    ),
);

$component = new LibreNMS\Component();
$hlsc = $component->getComponents($device['device_id'], $options);

$streams=array();

if (isset($hlsc[$device['device_id']])) {
    $id = $component->getFirstComponentID($hlsc, $device['device_id']);
    $streams = json_decode($hlsc[$device['device_id']][$id]['streams']);
}

foreach ($streams as $stream) {
    $graph_type            = 'hls_video';
    $graph_array['height'] = '100';
    $graph_array['width']  = '215';
    $graph_array['to'] = \LibreNMS\Config::get('time.now');
    $graph_array['id']     = $app['app_id'];
    $graph_array['type']   = 'application_hls_video';
    $graph_array['stream'] = $stream;

    echo '<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Stream: '.$stream.'</h3>
    </div>
    <div class="panel-body">
    <div class="row">';
    include 'includes/html/print-graphrow.inc.php';
    echo '</div>';
    echo '</div>';
    echo '</div>';
}
