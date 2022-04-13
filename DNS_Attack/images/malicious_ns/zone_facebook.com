$TTL 3D
@       IN      SOA   ns.facebook.com. admin.facebook.com. (
                2008111001
                8H
                2H
                4W
                1D)

@       IN      NS    ns.malicious.com.

@       IN      A     4.3.2.1
www     IN      A     5.3.2.1
ns      IN      A     10.9.0.171
*       IN      A     6.3.2.1
