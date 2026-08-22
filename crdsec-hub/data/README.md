# data/

Bind-mounted onto the container's `/var/lib/crowdsec/data` (see `../docker-compose.yml`). Not committed (see
`../.gitignore` - this file is the one deliberate exception).

Created and populated automatically by CrowdSec itself on `../crdsec-hub.sh up` - nothing here is meant to be
hand-edited. Notably includes `crowdsec.db` (the decision database - every alert/decision this hub has ever
processed) and CrowdSec's own enrichment data (GeoIP `.mmdb` files, IP/rDNS block-lists used by installed
collections), most of it symlinked from the image's own `/staging` rather than copied.
