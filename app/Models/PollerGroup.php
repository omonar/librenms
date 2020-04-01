<?php
/**
 * PollerGroup.php
 *
 * -Description-
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @package    LibreNMS
 * @link       http://librenms.org
 * @copyright  2020 Thomas Berberich
 * @author     Thomas Berberich <sourcehhdoctor@gmail.com>
 */

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class PollerGroup extends Model
{
    public $timestamps = false;
    protected $primaryKey = 'id';
    protected $fillable = ['group_name', 'descr'];

    /**
     * Initialize this class
     */
    public static function boot()
    {
        parent::boot();

        static::deleting(function (PollerGroup $pollergroup) {
            // handle device pollergroup fallback to default poller
            $default_poller_id = \LibreNMS\Config::get('distributed_poller_group');
            $pollergroup->devices()->update(['poller_group' => $default_poller_id]);
        });
    }

    public function devices()
    {
        return $this->hasMany('App\Models\Device', 'poller_group', 'id');
    }
}
