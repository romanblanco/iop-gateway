package identity;

use strict;
use warnings;
use JSON::PP;
use MIME::Base64;

sub set_identity_header {
    my $r = shift;

    my $ssl_client_s_dn = $r->variable("ssl_client_s_dn") // "";
    my $ssl_client_verify = $r->variable("ssl_client_verify") // "NONE";

    if ($ssl_client_s_dn eq "" || $ssl_client_verify ne "SUCCESS") {
        return _identity_from_forwarded($r);
    }

    my $org_id = $r->header_in("X-Org-Id") // "";
    my $cn;

    if ($org_id eq "") {
        if ($ssl_client_s_dn =~ /O=([^,]+)/) {
            $org_id = $1;
        } else {
            $r->log_error(0, "Missing O (org_id) in client certificate subject and no X-Org-Id header: $ssl_client_s_dn");
            return undef;
        }
    }

    if ($ssl_client_s_dn =~ /CN=([^,]+)/) {
        $cn = $1;
    } else {
        $r->log_error(0, "Missing CN in client certificate subject: $ssl_client_s_dn");
        return undef;
    }

    my $identity;
    my $forwarded = $r->header_in("Forwarded") // "";
    if ($forwarded eq "") {
        my $identity_type = $r->variable('identity_type') // "";
        if ($identity_type eq "associate") {
            $identity = {
                'identity' => {
                    'type' => 'Associate',
                    'auth_type' => 'saml-auth',
                    'associate' => {
                        'email' => 'iop-gateway@example.com',
                        'Role' => [],
                        'subject_dn' => 'iop-gateway',
                    },
                },
                'entitlements' => {
                    'insights' => { 'is_entitled' => JSON::PP::true },
                },
            };
        } else {
            $identity = {
                'identity' => {
                    'auth_type' => 'jwt-auth',
                    'org_id' => $org_id,
                    'internal' => { 'org_id' => $org_id },
                    'type' => 'User',
                    'user' => {
                        'email' => 'iop-gateway@example.com',
                        'first_name' => 'First',
                        'is_active' => JSON::PP::true,
                        'is_internal' => JSON::PP::true,
                        'is_org_admin' => JSON::PP::false,
                        'last_name' => 'Last',
                        'locale' => 'en_US',
                        'user_id' => '1',
                        'username' => $cn,
                    },
                },
                'entitlements' => {
                    'insights' => { 'is_entitled' => JSON::PP::true },
                },
            };
        }
    } else {
        my $owner_id;
        if ($forwarded =~ /for="?_([^,;"]+)"?/i) {
            $owner_id = $1;
        } else {
            $r->log_error(0, "Missing Forwarded for header value (as per RFC7239): $forwarded");
            return undef;
        }

        $identity = {
            'identity' => {
                'org_id' => $org_id,
                'internal' => { 'org_id' => $org_id },
                'type' => 'System',
                'auth_type' => 'cert-auth',
                'system' => {
                    'cn' => $owner_id,
                    'cert_type' => 'satellite',
                },
            },
            'entitlements' => {
                'insights' => { 'is_entitled' => JSON::PP::true },
            },
        };
    }

    return encode_base64(encode_json($identity), '');
}

sub _identity_from_forwarded {
    my $r = shift;

    my $forwarded = $r->header_in("Forwarded") // "";
    if ($forwarded eq "") {
        $r->log_error(0, "No client certificate and no Forwarded header, cannot identify request");
        return undef;
    }

    my $owner_id;
    if ($forwarded =~ /for="?_([^,;"]+)"?/i) {
        $owner_id = $1;
    } else {
        $r->log_error(0, "Missing Forwarded for header value (as per RFC7239): $forwarded");
        return undef;
    }

    my $org_id = $r->header_in("X-Org-Id") // "";
    if ($org_id eq "") {
        $r->log_error(0, "No client cert and no X-Org-Id header, rejecting request");
        return undef;
    }

    my $identity = {
        'identity' => {
            'org_id' => $org_id,
            'internal' => { 'org_id' => $org_id },
            'type' => 'System',
            'auth_type' => 'cert-auth',
            'system' => {
                'cn' => $owner_id,
                'cert_type' => 'satellite',
            },
        },
        'entitlements' => {
            'insights' => { 'is_entitled' => JSON::PP::true },
        },
    };

    return encode_base64(encode_json($identity), '');
}

1;
