## Room : https://tryhackme.com/room/securityfootage
## Overview
The **Security Footage** challenge involves analyzing a network capture file (`.pcap`) to recover a lost security camera feed. The goal is to extract the video from the packet capture and identify the flag hidden within.

---

## Step 1 — Analyze the PCAP
Open the provided `.pcap` file in **Wireshark**.

Sort by protocol to identify possible video streams:
1. Click the **Protocol** column header to sort.
2. If the stream isn't obvious via HTTP headers, the feed may be raw JPEGs over TCP.

---

## Step 2 — Extract JPEG Frames Using Foremost
We can use `foremost` to automatically carve JPEGs from the pcap.

```bash
foremost -i security-footage.pcap -o extracted/
```

This will output files to:
```
extracted/jpeg/
```

---

## Step 3 — Prepare Frames for Video Reconstruction
Check the extracted images:

```bash
ls -1 extracted/jpeg/
```

If filenames are non-continuous numbers (e.g., `1.jpg, 5.jpg, 1003.jpg`), rename them sequentially:

```bash
cd extracted/jpeg
a=1
for i in $(ls -1v *.jpg); do
    new=$(printf "frame_%04d.jpg" "$a")
    mv "$i" "$new"
    a=$((a+1))
done
```

---

## Step 4 — Rebuild the Video with FFmpeg
After renaming, run:

```bash
ffmpeg -framerate 10 -i frame_%04d.jpg -c:v libx264 -pix_fmt yuv420p reconstructed.mp4
```

- `-framerate 10` sets playback speed.
- `libx264` encodes as H.264 for compatibility.

---

## Step 5 — Find the Flag
Open `reconstructed.mp4` in a video player and carefully inspect the frames.
The flag is usually visible in a single frame, often displayed on a monitor or written somewhere in the scene.

---

## Tools Used
- **Wireshark** — packet analysis
- **Foremost** — file carving
- **ffmpeg** — video reconstruction

---

## Flag
```
<REDACTED_FLAG>
```

---

## Key Commands Summary
```bash
# Carve JPEGs from PCAP
foremost -i security-footage.pcap -o extracted/

# Rename to sequential order
cd extracted/jpeg
a=1; for i in $(ls -1v *.jpg); do new=$(printf "frame_%04d.jpg" "$a"); mv "$i" "$new"; a=$((a+1)); done

# Rebuild video
ffmpeg -framerate 10 -i frame_%04d.jpg -c:v libx264 -pix_fmt yuv420p reconstructed.mp4
```
