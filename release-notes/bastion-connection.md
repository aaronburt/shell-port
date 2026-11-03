## Changes

- A host can now connect through a bastion (jump host). In Add host or Edit host, choose **Connect via** and pick a host that connects directly. Shellport connects to the bastion first, then tunnels to the target, and both connections are logged.
- Session details show the route, and the connecting line names the bastion.
- Each passphrase prompt names the host it is for, so a bastion and its target can each ask for their own passphrase.

## After updating

- No action needed. Existing hosts still connect directly.
- To add or edit a host behind a bastion, Shellport logs in to the bastion to read the target's host key. The bastion's key must therefore have no passphrase, or the bastion must log in with a password.
