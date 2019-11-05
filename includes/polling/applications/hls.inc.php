<?php

use LibreNMS\RRD\RrdDefinition;

$name = 'hls';
$app_id = $app['app_id'];
if (!empty($agent_data['app'][$name])) {
    $lines = explode("\n", $agent_data['app'][$name]);
    rsort($lines);

    $streams = [];
    $metrics = [];
    $data = array();

    $total_bitrate_video = 0;
    $total_bitrate_audio = 0;

    foreach($lines as $item => $line) {
        $line = trim($line);

        if (!empty($line)) {
            $data = explode(" ", $line, 3);

            $streams[] = $data[0];

            $rrd_name = array('app', $name, $app_id, $data[0]);
            $rrd_def = RrdDefinition::make()
                ->addDataset('bitrate_video', 'GAUGE', 0, 125000000000)
                ->addDataset('bitrate_audio', 'GAUGE', 0, 125000000000);

            $fields = array(
                'bitrate_video' => $data[1],
                'bitrate_audio' => $data[2],
            );

            $total_bitrate_video = $total_bitrate_video + $data[1];
            $total_bitrate_audio = $total_bitrate_audio + $data[2];

            $metrics["video_$line"] = $fields;
            $tags = compact('name', 'app_id', 'rrd_name', 'rrd_def');
            data_update($device, 'app', $tags, $fields);
        }
    }

    $rrd_name = array('app', $name, $app_id);
    $rrd_def = RrdDefinition::make()
        ->addDataSet('total_bitrate_video', 'GAUGE', 0, 125000000000)
        ->addDataSet('total_bitrate_audio', 'GAUGE', 0, 125000000000);

    $fields = array(
        'total_bitrate_video' => $total_bitrate_video,
        'total_bitrate_audio' => $total_bitrate_audio,
    );

    $metrics['multi_video'] = $fields;

    $tags = compact('name', 'app_id', 'rrd_name', 'rrd_def');
    data_update($device, 'app', $tags, $fields);

    update_application($app, 'ok', $metrics);

    //
    // component processing for hls
    //
    $device_id = $device['device_id'];
    $options=array(
        'filter' => array(
            'type' => array('=', 'hls'),
        ),
    );
    $component = new LibreNMS\Component();
    $hls_components = $component->getComponents($device_id, $options);
    // if no stream, delete hls components
    if (empty($streams)) {
        if (isset($hls_components[$device_id])) {
                foreach ($hls_components[$device_id] as $component_id => $_unused) {
                    $component->deleteComponent($component_id);
            }
        }
    } else {
        if (isset($hls_components[$device_id])) {
            $hlsc = $hls_components[$device_id];
        } else {
            $hlsc = $component->createComponent($device_id, 'hls');
        }
        $id = $component->getFirstComponentID($hlsc);
        $hlsc[$id]['label'] = 'HLS Streams';
        $hlsc[$id]['streams'] = json_encode($streams);
        $component->setComponentPrefs($device_id, $hlsc);
    }
}
