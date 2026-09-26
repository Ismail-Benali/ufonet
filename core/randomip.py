#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This file is part of the UFONet project, https://ufonet.03c8.net

Copyright (c) 2013/2026 | psy <epsylon@riseup.net>

You should have received a copy of the GNU General Public License along
with UFONet; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import secrets
import ipaddress

_RESERVED_FIRST_OCTETS = frozenset({0, 10, 127, 169, 172, 192})
_MAX_OCTET = 256


class RandomIP(object):
    """
    Class to generate random valid IP's
    """
    def _generateip(self, string=""):
        """
        Generate a random valid IP address suitable for X-Forwarded-For.
        Avoids reserved, private, and special-use addresses.

        Args:
            string: Unused parameter kept for backward compatibility.

        Returns:
            str: A random valid public IPv4 address string.
        """
        while True:
            first = secrets.randbelow(_MAX_OCTET - 1) + 1  # 1..255
            if first in _RESERVED_FIRST_OCTETS:
                continue

            second = secrets.randbelow(_MAX_OCTET)  # 0..255
            third = secrets.randbelow(_MAX_OCTET)  # 0..255
            fourth = secrets.randbelow(_MAX_OCTET)  # 0..255

            # Validate full IP against reserved ranges
            try:
                ip_str = f"{first}.{second}.{third}.{fourth}"
                addr = ipaddress.IPv4Address(ip_str)

                # Check reserved categories
                if not addr.is_global:
                    continue
                if addr.is_multicast:
                    continue
                if addr.is_reserved:
                    continue
                if addr.is_unspecified:
                    continue
                if addr.is_loopback:
                    continue
                if addr.is_private:
                    continue
                if addr.is_link_local:
                    continue

                # Additional checks for specific ranges not caught by ipaddress
                if first == 169 and second == 254:
                    continue  # 169.254.x.x link-local
                if first == 100 and 64 <= second <= 127:
                    continue  # 100.64.x.x CGNAT
                if first == 192 and second == 0:
                    if third in ({0, 2}):
                        continue  # 192.0.2.x TEST-NET, 192.0.0.x
                if first == 198 and second == 18:
                    continue  # 198.18.x.x benchmarking
                if 224 <= first <= 239:
                    continue  # multicast

                return ip_str
            except ValueError:
                continue

    def generate(self, string=""):
        """
        Generate a random valid IP address.

        Alias for _generateip for compatibility.

        Args:
            string: Unused parameter.

        Returns:
            str: A random valid public IPv4 address string.
        """
        return self._generateip(string)


def generate_random_public_ip() -> str:
    """
    Generate a random valid public IP address suitable for X-Forwarded-For.

    Returns:
        str: A random valid public IPv4 address string.
    """
    rip = RandomIP()
    return rip.generate()