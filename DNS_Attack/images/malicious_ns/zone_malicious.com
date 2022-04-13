$TTL 3D
@       IN      SOA   ns.malicious.com. admin.malicious.com. (
                2008111001
                8H
                2H
                4W
                1D)

@       IN      NS    ns.malicious.com.

@       IN      A     10.9.0.160
www     IN      A     10.9.0.160
ns      IN      A     10.9.0.171
*       IN      A     10.9.0.50
