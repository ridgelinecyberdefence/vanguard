package remote

import "testing"

func TestRemoteTargetValidate(t *testing.T) {
	cases := []struct {
		name   string
		target RemoteTarget
		ok     bool
	}{
		{
			name: "valid linux ssh target",
			target: RemoteTarget{
				Hostname: "host01.internal", IPAddress: "10.0.0.1",
				OSType: "linux", Protocol: "ssh", Port: 22,
				Username: "root", AuthMethod: "password",
			},
			ok: true,
		},
		{
			name: "valid windows winrm target with domain user",
			target: RemoteTarget{
				Hostname: "DC01", OSType: "windows", Protocol: "winrm",
				Port: 5985, Username: "CORP\\Administrator",
				AuthMethod: "password",
			},
			ok: true,
		},
		{
			name: "hostname with shell metachar rejected",
			target: RemoteTarget{
				Hostname: "host;rm -rf /", OSType: "linux",
				Protocol: "ssh", Port: 22, Username: "root", AuthMethod: "password",
			},
		},
		{
			name: "username with backtick rejected",
			target: RemoteTarget{
				Hostname: "host", OSType: "linux", Protocol: "ssh",
				Port: 22, Username: "admin`id`", AuthMethod: "password",
			},
		},
		{
			name: "invalid IP rejected",
			target: RemoteTarget{
				IPAddress: "999.999.999.999", OSType: "linux",
				Protocol: "ssh", Port: 22, Username: "root", AuthMethod: "password",
			},
		},
		{
			name: "port out of range rejected",
			target: RemoteTarget{
				Hostname: "host", OSType: "linux", Protocol: "ssh",
				Port: 99999, Username: "root", AuthMethod: "password",
			},
		},
		{
			name: "missing hostname AND ip rejected",
			target: RemoteTarget{
				OSType: "linux", Protocol: "ssh", Port: 22,
				Username: "root", AuthMethod: "password",
			},
		},
		{
			name: "key auth without key path rejected",
			target: RemoteTarget{
				Hostname: "host", OSType: "linux", Protocol: "ssh",
				Port: 22, Username: "root", AuthMethod: "key",
			},
		},
		{
			name: "unsupported protocol rejected",
			target: RemoteTarget{
				Hostname: "host", OSType: "linux", Protocol: "telnet",
				Port: 23, Username: "root", AuthMethod: "password",
			},
		},
	}

	for _, c := range cases {
		err := c.target.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: expected ok, got error: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected validation error, got nil", c.name)
		}
	}
}
