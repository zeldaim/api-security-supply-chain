#!/usr/bin/env bash
# 실제 화면 녹화: 컨테이너 안에 가상 화면을 띄우고, 그 터미널에서 live_demo.sh 를 실행하면서 화면을 캡처한다.
#   bash record_live.sh         → demo_live.mp4 (실시간) · demo_live_2x.mp4 (2배속)
# 필요: crAPI 기동, e2e-runner · wazuh-manager 이미지, crapi_run3 의 모델(state/B), demo-rec 이미지(Dockerfile.rec)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"; WIN_REPO="$(cd "$REPO" && pwd -W 2>/dev/null || echo "$REPO")"
export MSYS_NO_PATHCONV=1
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$WIN_REPO:/repo" -e WIN_REPO="$WIN_REPO" demo-rec bash -c '
  Xvfb :99 -screen 0 1280x720x24 >/dev/null 2>&1 & sleep 2; export DISPLAY=:99
  O=/repo/e2e_story/demo_video_2026-11-16
  ffmpeg -y -loglevel error -f x11grab -draw_mouse 0 -framerate 10 -video_size 1280x720 -i :99 -c:v libx264 -preset veryfast -crf 26 -pix_fmt yuv420p $O/demo_live.mp4 & FF=$!
  sleep 1
  xterm -u8 -fa "DejaVu Sans Mono" -fd "NanumGothicCoding" -fs 11 -geometry 140x38+0+0 -bg "#10121a" -fg "#dde2e8" -b 8 -e bash /repo/e2e_story/demo_video_2026-11-16/live_demo.sh
  sleep 1; kill -INT $FF; wait $FF 2>/dev/null
  ffmpeg -y -loglevel error -i $O/demo_live.mp4 -filter:v "setpts=0.5*PTS" -an -c:v libx264 -crf 26 -pix_fmt yuv420p -movflags +faststart $O/demo_live_2x.mp4
  for f in demo_live demo_live_2x; do echo "$f.mp4 $(ffprobe -v error -show_entries format=duration -of csv=p=0 $O/$f.mp4 | cut -d. -f1)초"; done'
