<?php

/**
 * Pure-PHP implementation of ECDSA.
 *
 * PHP version 5
 *
 * @category  Crypt
 * @package   ECDSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace LibreNMS\Crypt;

use LibreNMS\Math\BigInteger;

/**
 * Pure-PHP PKCS#1 compliant implementation of ECDSA.
 *
 * @package ECDSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class ECDSA
{
    /**#@+
     * @access private
     * @see \phpseclib\Crypt\ECDSA::__construct()
    */

    /**
     * Precomputed Zero
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    var $zero;

    /**
     * Precomputed One
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    var $one;

    /**
     * Private key
     *
     * @var string
     * @access private
     */
    var $private_key;

    /**
     * Private key
     *
     * @var string
     * @access private
     */
    var $private_key_pem;

    /**
     * Public key
     *
     * @var string
     * @access private
     */
    var $public_key;

    /**
     * Order of generator point
     *
     * @var string
     * @access private
     */
    var $order;

    /**
     * Hash
     *
     * @var string
     * @access private
     */
    var $hash;

    /**
     * Hash size
     *
     * @var string
     * @access private
     */
    var $hash_size;

    /**
     * ECDSA scheme
     *
     * @var string
     * @access private
     */
    var $scheme;

    /**
     * The constructor
     *
     * @return \phpseclib\Crypt\ECDSA
     * @access public
     */
    function __construct()
    {
        $this->zero = new BigInteger();
        $this->one = new BigInteger(1);

        $this->hash = 'sha256';
        $this->hash_size = 32;
    }

    /**
     * Loads a public or private key
     *
     * Returns true on success and false on failure (ie. an incorrect password was provided or the key was malformed)
     *
     * @access public
     * @param string $key
     */
    function loadKey($key)
    {
        if (strpos($key, 'BEGIN EC PRIVATE KEY') !== false) {
            $this->private_key_pem = $key;

            $key = preg_replace('#(?:^-.*?-[\r\n]*$)|\s#ms', '', $key);
            $key = base64_decode($key);

            extract(unpack('Ctype', substr($key, 0, 1)));
            extract(unpack('Cremaining_bytes', substr($key, 1, 1)));

            $offset = 2;
            if ($remaining_bytes & 0x80) {
                extract(unpack('Cremaining_bytes', substr($key, $offset, 1)));
                $offset = $offset + 1;
            }

            while ($remaining_bytes > 0) {
                extract(unpack('Cidentifier', substr($key, $offset, 1)));
                extract(unpack('Clength', substr($key, $offset + 1, 1)));

                $offset = $offset + 2;
                $remaining_bytes = $remaining_bytes - 2;

                if ($length & 0x80) {
                    extract(unpack('Clength', substr($key, $offset, 1)));
                    $offset = $offset + 1;
                    $remaining_bytes = $remaining_bytes - 1;
                }

                switch ($identifier) {
                    case 0x03:
                        $public_key = substr($key, $offset + 1, $length - 1);
                        $offset = $offset + $length;
                        $remaining_bytes = $remaining_bytes - $length;
                        break;
                    case 0x04:
                        $private_key = substr($key, $offset, $length);
                        $offset = $offset + $length;
                        $remaining_bytes = $remaining_bytes - $length;
                        break;
                    case 0x06:
                        $curve_oid = substr($key, $offset, $length);
                        $offset = $offset + $length;
                        $remaining_bytes = $remaining_bytes - $length;
                        break;
                    case 0xa0:
                    case 0xa1:
                        break;
                    default:
                        $offset = $offset + $length;
                        $remaining_bytes = $remaining_bytes - $length;
                }
            }

            $curve_oid = bin2hex($curve_oid);
            switch ($curve_oid) {
                case '2a8648ce3d030107':
                    $this->scheme = 'nistp256';
                    $this->private_key = $private_key;
                    $this->public_key = $public_key;
                    $this->order = new BigInteger('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16);
                    $this->hash = 'sha256';
                    $this->hash_size = 32;
                    break;
                case '2b81040022':
                    $this->scheme = 'nistp384';
                    $this->private_key = $private_key;
                    $this->public_key = $public_key;
                    $this->order = new BigInteger('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973', 16);
                    $this->hash = 'sha384';
                    $this->hash_size = 48;
                    break;
                case '2b81040023':
                    $this->scheme = 'nistp521';
                    $this->private_key = $private_key;
                    $this->public_key = $public_key;
                    $this->order = new BigInteger('01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409', 16);
                    $this->hash = 'sha512';
                    $this->hash_size = 64;
                    break;
                default:
                    user_error('Unsupported ECDSA key format');
                    return false;
            }

            return true;
        }

        user_error('Unsupported ECDSA key format');
        return false;
    }

    /**
     * Gets ECDSA scheme
     *
     * @access public
     * @return string
     */
    function getScheme()
    {
        return $this->scheme;
    }

    /**
     * Gets hash scheme for ECDSA signature
     *
     * @access public
     * @return string
     */
    function getHash()
    {
        return $this->hash;
    }

    /**
     * Gets hash size for ECDSA signature
     *
     * @access public
     * @return string
     */
    function getHashSize()
    {
        return $this->hash_size;
    }

    /**
     * Gets order of generator
     *
     * @access public
     * @return string
     */
    function getOrder()
    {
        return $this->order;
    }

    /**
     * Gets ECDSA private key
     *
     * @access public
     * @return string
     */
    function getPrivateKey()
    {
        return $this->private_key;
    }

    /**
     * Gets ECDSA private key in pem format
     *
     * @access public
     * @return string
     */
    function getPrivateKeyPem()
    {
        return $this->private_key_pem;
    }

    /**
     * Gets ECDSA public key
     *
     * @access public
     * @return string
     */
    function getPublicKey()
    {
        return $this->public_key;
    }

    /**
     * Doubles a jacobian coordinate on the curve
     *
     * Algorithm: dbl-2004-hmv
     * Cost: 4M + 4S + 1*half + 5add + 2add (2*2) + 2add (1*3).
     * Source: http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
     *
     * @return array
     * @access private
     */
    function _doublePoint(array $p, BigInteger $m)
    {
        if (empty($p)) {
            return [];
        }

        list($x1, $y1, $z1) = $p;

        /* t1 = z1 * z1 */
        $t1 = $z1->multiply($z1);
        list(, $t1) = $t1->divide($m);
        /* t2 = x1 - t1 */
        $t2 = $x1->subtract($t1);
        if ($x1->compare($t1) < 0) {
            $t2 = $t2->add($m);
        }
        /* t1 = x1 + t1 */
        $t1 = $x1->add($t1);
        if ($t1->compare($m) >= 0) {
            $t1 = $t1->subtract($m);
        }
        /* t2 = t1 * t2 */
        $t2 = $t1->multiply($t2);
        list(, $t2) = $t2->divide($m);
        /* t1 = t2 + t2 */
        $t1 = $t2->add($t2);
        if ($t1->compare($m) >= 0) {
            $t1 = $t1->subtract($m);
        }
        /* t2 = t1 + t2 */
        $t2 = $t1->add($t2);
        if ($t2->compare($m) >= 0) {
            $t2 = $t2->subtract($m);
        }
        /* y3 = y1 + y1 */
        $y3 = $y1->add($y1);
        if ($y3->compare($m) >= 0) {
            $y3 = $y3->subtract($m);
        }
        /* z3 = y3 * z1 */
        $z3 = $y3->multiply($z1);
        list(, $z3) = $z3->divide($m);
        /* y3 = y3 * y3 */
        $y3 = $y3->multiply($y3);
        list(, $y3) = $y3->divide($m);
        /* t3 = y3 * x1 */
        $t3 = $y3->multiply($x1);
        list(, $t3) = $t3->divide($m);
        /* y3 = y3 * y3 */
        $y3 = $y3->multiply($y3);
        list(, $y3) = $y3->divide($m);
        /* y3 = y3/2 */
        if ($y3->isOdd()) {
            $y3 = $y3->add($m);
        }
        $y3 = $y3->bitwise_rightShift(1);
        /* x3 = t2 * t2 */
        $x3 = $t2->multiply($t2);
        list(, $x3) = $x3->divide($m);
        /* t1 = t3 + t3 */
        $t1 = $t3->add($t3);
        if ($t1->compare($m) >= 0) {
            $t1 = $t1->subtract($m);
        }
        /* x3 = x3 - t1 */
        if ($x3->compare($t1) < 0) {
            $x3 = $x3->add($m);
        }
        $x3 = $x3->subtract($t1);
        /* t1 = t3 - x3 */
        $t1 = $t3->subtract($x3);
        if ($t3->compare($x3) < 0) {
            $t1 = $t1->add($m);
        }
        /* t1 = t2 * t1 */
        $t1 = $t2->multiply($t1);
        list(, $t1) = $t1->divide($m);
        /* y3 = t1 - y3 */
        if ($t1->compare($y3) < 0) {
            $t1 = $t1->add($m);
        }
        $y3 = $t1->subtract($y3);

        return [$x3, $y3, $z3];
    }

    /**
     * Adds two jacobian coordinates on the curve
     *
     * Algorithm: add-1998-cmo-2
     * Cost: 12M + 4S + 6add + 1add (1*2).
     * Source: http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
     *
     * @return array
     * @access private
     */
    function _addPoint(array $p, array $q, BigInteger $m)
    {
        if (empty($p)) {
            return $q;
        }

        if (empty($q)) {
            return $p;
        }

        list($x1, $y1, $z1) = $p;
        list($x2, $y2, $z2) = $q;

        /* z12 = z1 * z1 */
        $z12 = $z1->multiply($z1);
        list(, $z12) = $z12->divide($m);
        /* z22 = z2 * z2 */
        $z22 = $z2->multiply($z2);
        list(, $z22) = $z22->divide($m);
        /* u1 = x1 * z2 * z2 */
        $u1 = $x1->multiply($z22);
        list(, $u1) = $u1->divide($m);
        /* u2 = x2 * z1 * z1 */
        $u2 = $x2->multiply($z12);
        list(, $u2) = $u2->divide($m);

        /* s1 = y1 * z2 * z2 * z2 */
        $s1 = $z2->multiply($z22);
        list(, $s1) = $s1->divide($m);
        $s1 = $s1->multiply($y1);
        list(, $s1) = $s1->divide($m);

        /* s2 = y2 * z1 * z1 * z1 */
        $s2 = $z1->multiply($z12);
        list(, $s2) = $s2->divide($m);
        $s2 = $s2->multiply($y2);
        list(, $s2) = $s2->divide($m);

        /* h = u2 - u1 */
        $h = $u2->subtract($u1);
        if ($u2->compare($u1) < 0) {
            $h = $h->add($m);
        }

        /* r = s2 - s1 */
        $r = $s2->subtract($s1);
        if ($s2->compare($s1) < 0) {
            $r = $r->add($m);
        }

        /* h2 = h * h */
        $h2 = $h->multiply($h);
        list(, $h2) = $h2->divide($m);
        /* h3 = h * h * h */
        $h3 = $h->multiply($h2);
        list(, $h3) = $h3->divide($m);
        /* v = u1 * h * h */
        $v = $u1->multiply($h2);
        list(, $v) = $v->divide($m);

        /* x3 = r * r - h * h * h - 2 * v */
        $x3 = $r->multiply($r);
        list(, $x3) = $x3->divide($m);
        if ($x3->compare($h3) < 0) {
            $x3 = $x3->add($m);
        }
        $x3 = $x3->subtract($h3);

        if ($x3->compare($v) < 0) {
            $x3 = $x3->add($m);
        }
        $x3 = $x3->subtract($v);

        if ($x3->compare($v) < 0) {
            $x3 = $x3->add($m);
        }
        $x3 = $x3->subtract($v);

        /* y3 = r * (v - x3) - s1 * h *h * h  */
        $y3 = $v->subtract($x3);
        if ($v->compare($x3) < 0) {
            $y3 = $y3->add($m);
        }
        $y3 = $y3->multiply($r);
        list(, $y3) = $y3->divide($m);
        $s1 = $s1->multiply($h3);
        list(, $s1) = $s1->divide($m);
        if ($y3->compare($s1) < 0) {
            $y3 = $y3->add($m);
        }
        $y3 = $y3->subtract($s1);

        /* z3 = z1 * z2 * h */
        $z3 = $z1->multiply($z2);
        list(, $z3) = $z3->divide($m);
        $z3 = $z3->multiply($h);
        list(, $z3) = $z3->divide($m);

        return [$x3, $y3, $z3];
    }

    /**
     * Subtracts two jacobian coordinates on the curve
     *
     * Algorithm: add-1998-cmo-2
     * Cost: 12M + 4S + 6add + 1add (1*2).
     * Source: http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
     *
     * @return array
     * @access private
     */
    function _subPoint(array $p, array $q, BigInteger $m)
    {
        $q[1] = $m->subtract($q[1]);

        if (empty($p)) {
            return $q;
        }

        list($x1, $y1, $z1) = $p;
        list($x2, $y2, $z2) = $q;

        /* z12 = z1 * z1 */
        $z12 = $z1->multiply($z1);
        list(, $z12) = $z12->divide($m);
        /* z22 = z2 * z2 */
        $z22 = $z2->multiply($z2);
        list(, $z22) = $z22->divide($m);
        /* u1 = x1 * z2 * z2 */
        $u1 = $x1->multiply($z22);
        list(, $u1) = $u1->divide($m);
        /* u2 = x2 * z1 * z1 */
        $u2 = $x2->multiply($z12);
        list(, $u2) = $u2->divide($m);

        /* s1 = y1 * z2 * z2 * z2 */
        $s1 = $z2->multiply($z22);
        list(, $s1) = $s1->divide($m);
        $s1 = $s1->multiply($y1);
        list(, $s1) = $s1->divide($m);

        /* s2 = y2 * z1 * z1 * z1 */
        $s2 = $z1->multiply($z12);
        list(, $s2) = $s2->divide($m);
        $s2 = $s2->multiply($y2);
        list(, $s2) = $s2->divide($m);

        /* h = u2 - u1 */
        $h = $u2->subtract($u1);
        if ($u2->compare($u1) < 0) {
            $h = $h->add($m);
        }

        /* r = s2 - s1 */
        $r = $s2->subtract($s1);
        if ($s2->compare($s1) < 0) {
            $r = $r->add($m);
        }

        /* h2 = h * h */
        $h2 = $h->multiply($h);
        list(, $h2) = $h2->divide($m);
        /* h3 = h * h * h */
        $h3 = $h->multiply($h2);
        list(, $h3) = $h3->divide($m);
        /* v = u1 * h * h */
        $v = $u1->multiply($h2);
        list(, $v) = $v->divide($m);

        /* x3 = r * r - h * h * h - 2 * v */
        $x3 = $r->multiply($r);
        list(, $x3) = $x3->divide($m);
        if ($x3->compare($h3) < 0) {
            $x3 = $x3->add($m);
        }
        $x3 = $x3->subtract($h3);

        if ($x3->compare($v) < 0) {
            $x3 = $x3->add($m);
        }
        $x3 = $x3->subtract($v);

        if ($x3->compare($v) < 0) {
            $x3 = $x3->add($m);
        }
        $x3 = $x3->subtract($v);

        /* y3 = r * (v - x3) - s1 * h *h * h  */
        $y3 = $v->subtract($x3);
        if ($v->compare($x3) < 0) {
            $y3 = $y3->add($m);
        }
        $y3 = $y3->multiply($r);
        list(, $y3) = $y3->divide($m);
        $s1 = $s1->multiply($h3);
        list(, $s1) = $s1->divide($m);
        if ($y3->compare($s1) < 0) {
            $y3 = $y3->add($m);
        }
        $y3 = $y3->subtract($s1);

        /* z3 = z1 * z2 * h */
        $z3 = $z1->multiply($z2);
        list(, $z3) = $z3->divide($m);
        $z3 = $z3->multiply($h);
        list(, $z3) = $z3->divide($m);

        return [$x3, $y3, $z3];
    }

    /**
     * Precomputes scalars in Joint Sparse Form
     *
     * Adapted from https://git.io/vxrpD
     *
     * @return int[]
     */
    function _getJointSparseForm(BigInteger $d, BigInteger $e)
    {
        $jsf = [[], []];

        $bit_d = 0;
        $bit_e = 0;

        while ($d->compare(new BigInteger(-$bit_d)) > 0 || $e->compare(new BigInteger(-$bit_e)) > 0) {
            // First phase
            $l_d_mods4 = ($d->testBit(0) + 2 * $d->testBit(1) + $bit_d) & 3;
            $l_e_mods4 = ($e->testBit(0) + 2 * $e->testBit(1) + $bit_e) & 3;

            if ($l_d_mods4 == 3) {
                $l_d_mods4 = -1;
            }
            if ($l_e_mods4 == 3) {
                $l_e_mods4 = -1;
            }

            $u_d = 0;
            if ($l_d_mods4 & 1) { // if $l_d_mods4 is odd
                $l_d_mod8 = ($d->testBit(0) + 2 * $d->testBit(1) + 4 * $d->testBit(2) + $bit_d) & 7;
                $u_d  = ($l_d_mod8 == 3 || $l_d_mod8 == 5) && $l_e_mods4 == 2 ? -$l_d_mods4 : $l_d_mods4;
            }
            $jsf[0][] = $u_d;

            $u_e = 0;
            if ($l_e_mods4 & 1) { // if $l_e_mods4 is odd
                $l_e_mod8 = ($e->testBit(0) + 2 * $e->testBit(1) + 4 * $e->testBit(2) + $bit_e) & 7;
                $u_e  = ($l_e_mod8 == 3 || $l_e_mod8 == 5) && $l_d_mods4 == 2 ? -$l_e_mods4 : $l_e_mods4;
            }
            $jsf[1][] = $u_e;

            // Second phase
            if (2 * $bit_d == $u_d + 1) {
                $bit_d = 1 - $bit_d;
            }
            if (2 * $bit_e == $u_e + 1) {
                $bit_e = 1 - $bit_e;
            }
            $d = $d->bitwise_rightShift(1);
            $e = $e->bitwise_rightShift(1);
        }

        return $jsf;
    }

    /**
     * Multiply points on the curve by respective scalars and add them.
     *
     * Uses the fast Shamir method w/ joint sparse form representation of scalars
     *
     * This function does not need to be resistant to timing attacks because
     * it is used to verify signature where scalars d and e are public.
     *
     * @return array
     * @access public
     */
    function multiplyAddPoints(array $p, BigInteger $d, array $q, BigInteger $e, BigInteger $m)
    {
        list($d, $e) = self::_getJointSparseForm($d, $e);
        $max = count($d);

        $p_add_q = self::_addPoint($p, $q, $m);
        $p_sub_q = self::_subPoint($p, $q, $m);

        $r = [];
        for ($i = 0; $i < $max; $i++)  {
            /* Joint Sparse Form is right-to-left so we need
             * to read the bits in the reverse order.
             */
            $e_i = $e[$max - $i - 1];
            $d_i = $d[$max - $i - 1];

            if ($i > 0) {
                $r = self::_doublePoint($r, $m);
            };

            $idx = 3 * $d_i + $e_i;
            switch ($idx) {
                case -4:
                    /* d_i = -1, e_i = -1 */
                    $r = self::_subPoint($r, $p_add_q, $m);
                    break;
                case -3:
                    /* d_i = -1, e_i = 0 */
                    $r = self::_subPoint($r, $p, $m);
                    break;
                case -2:
                    /* d_i = -1, e_i = 1 */
                    $r = self::_subPoint($r, $p_sub_q, $m);
                    break;
                case -1:
                    /* d_i = 0, e_i = -1 */
                    $r = self::_subPoint($r, $q, $m);
                    break;
                case 1:
                    /* d_i = 0, e_i = 1 */
                    $r = self::_addPoint($r, $q, $m);
                    break;
                case 2:
                    /* d_i = 1, e_i = -1 */
                    $r = self::_addPoint($r, $p_sub_q, $m);
                    break;
                case 3:
                    /* d_i = 1, e_i = 0 */
                    $r = self::_addPoint($r, $p, $m);
                    break;
                case 4:
                    /* d_i = 1, e_i = 1 */
                    $r = self::_addPoint($r, $p_add_q, $m);
                    break;
                default:
            }
        }

        return $r;
    }

    /**
     * Multiply point on the curve by respective scalar.
     *
     *
     * This function needs to be resistant to timing attacks because it
     * is used to generate signature where scalar d should remain secret
     *
     * @return array
     * @access public
     */
    function multiplyPoint(array $p, BigInteger $d, BigInteger $m)
    {
        $r = [[], $p];

        $d = $d->toBits();
        for ($i = 0; $i < strlen($d); $i++)  {
            $d_i = (int) $d[$i];

            $r[1 - $d_i] = self::_addPoint($r[0], $r[1], $m);
            $r[$d_i] = self::_doublePoint($r[$d_i], $m);
        }

        return $r[0];
    }

    /**
     * Generate a deterministic K for ECDSA signing algorithm.
     *
     * Based on RFC 6979
     *
     * @return BigInteger
     * @access public
     */
    function generateKvalue($message, $privatekey)
    {
        $hash_algorithm = $privatekey->getHash();
        $hash_size = $privatekey->getHashSize();
        $ecdsa_private_key = $privatekey->getprivateKey();

        $q = $privatekey->getOrder();
        $qlen = strlen($q->toBits());

        /* Step a */
        $h1 = hash($hash_algorithm, $message, true);

        /* Step b */
        $v = str_pad('', $hash_size, '\x01', STR_PAD_LEFT);

        /* Step c */
        $k = str_pad('', $hash_size, '\x00', STR_PAD_LEFT);

        /* Step d */
        $m = $v . '\x00' . $ecdsa_private_key . $h1;
        $k = hash_hmac($hash_algorithm, $m, $k, true);

        /* Step e */
        $v = hash_hmac($hash_algorithm, $v, $k, true);

        /* Step f */
        $m = $v . '\x01' . $ecdsa_private_key . $h1;
        $k = hash_hmac($hash_algorithm, $m, $k, true);

        /* Step g */
        $v = hash_hmac($hash_algorithm, $v, $k, true);

        /* Step h */
        for (;;) {
            /* Phase 1 */
            $t = '';

            /* Phase 2 */
            do {
                $v = hash_hmac($hash_algorithm, $v, $k, true);
                $t = $t . $v;

                $k = new BigInteger($t, 256);
                $klen = strlen($k->toBits());
            } while ($klen < $qlen);

            /* Phase 3 */
            $k = $k->bitwise_rightShift($klen - $qlen);

            if ($k->compare($q) < 0) {
                return $k;
            }

            $k = hash_hmac($hash_algorithm, $v . '\x00', $k, true);
            $v = hash_hmac($hash_algorithm, $v, $k, true);
        }
    }
}
