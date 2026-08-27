#!/bin/sh
# Record the demo to demo/depot.cast.
#
# The program itself finishes in well under a second, which is the truth and
# also unwatchable — asciinema would flash the whole night past in one frame.
# So playback is PACED here, in the recorder, and not in the demo: a line at a
# time, with a beat between acts. Nothing about what runs changes; only how
# fast a viewer sees it.
set -e
cd "$(dirname "$0")/.."
asciinema rec demo/depot.cast --overwrite --cols 78 --rows 66 --idle-time-limit 2 -c "sh demo/paced.sh"
