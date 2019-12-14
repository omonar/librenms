<?php
/*
 * LibreNMS
 *
 * Copyright (c) 2016 Søren Friis Rosiak <sorenrosiak@gmail.com>
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.  Please see LICENSE.txt at the top level of
 * the source code distribution for details.
 */
namespace LibreNMS\Alert\Transport;

use LibreNMS\Alert\Transport;

class Msteams extends Transport
{
    public function deliverAlert($obj, $opts)
    {
        if (!empty($this->config)) {
            $opts['url'] = $this->config['msteam-url'];
        }
        
        return $this->contactMsteams($obj, $opts);
    }

    public function contactMsteams($obj, $opts)
    {
        $url   = $opts['url'];
        
        $data  = array(
            'title' => $obj['title'],
            'themeColor' => self::getColorForState($obj['state']),
            'text' => strip_tags($obj['msg'], '<strong><em><h1><h2><h3><strike><ul><ol><li><pre><blockquote><a><img><p>')
        );
        $curl  = curl_init();
        set_curl_proxy($curl);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            'Content-type' => 'application/json',
            'Expect:'
        ));
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
        $ret  = curl_exec($curl);
        $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);

        if ($code != 200) {
            var_dump("Microsoft Teams returned Error, retry later");
            return false;
        }
        return true;
    }
    
    /**
     * Get the hex color string for a particular state
     * @param integer $state State code from alert
     * @return string Hex color, default to #337AB7 blue if state unrecognised
     */
    public static function getColorForState($state)
    {
        $colors = array(
            0 => '#00FF00', // OK - green
            1 => '#FF0000', // Bad - red
            2 => '#337AB7', // Acknowledged - blue
            3 => '#FF0000', // Worse - red
            4 => '#F0AD4E', // Better - yellow
        );
        
        return isset($colors[$state]) ? $colors[$state] : '#337AB7';
    }

    public static function configTemplate()
    {
        return [
            'config' => [
                [
                    'title' => 'Webhook URL',
                    'name' => 'msteam-url',
                    'descr' => 'Microsoft Teams Webhook URL',
                    'type' => 'text',
                ]
            ],
            'validation' => [
                'msteam-url' => 'required|url'
            ]
        ];
    }
}
