"""Owned loopback SFU with actual HTTP-issued tokens; private input stays on stdin."""
import asyncio
import base64
import json
import math
import os
import socket
import struct
import subprocess
import sys
import tempfile

from livekit import rtc


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as lease:
        lease.bind(("127.0.0.1", 0))
        return lease.getsockname()[1]


async def run(data):
    config = {
        "port": data["port"], "bind_addresses": ["127.0.0.1"],
        "keys": {data["api_key"]: data["api_secret"]},
        "rtc": {"tcp_port": port(), "udp_port": port(socket.SOCK_DGRAM),
                "node_ip": "127.0.0.1", "use_external_ip": False},
        "logging": {"level": "error"},
    }
    with tempfile.TemporaryDirectory(prefix="2141-consent-sfu-") as root:
        path = os.path.join(root, "livekit.yaml")
        with open(path, "w", encoding="utf-8") as file:
            json.dump(config, file)
        server = subprocess.Popen(
            [data["livekit_bin"], "--config", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        rooms = [rtc.Room(), rtc.Room()]
        tasks = []
        frames = {"audio": 0, "video": 0}
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("owned SFU exited")
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", data["port"])
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
            else:
                raise RuntimeError("owned SFU startup timed out")

            async def consume(track, kind):
                stream = rtc.AudioStream(track) if kind == "audio" else rtc.VideoStream(track)
                try:
                    async for _ in stream:
                        frames[kind] += 1
                finally:
                    await stream.aclose()

            @rooms[0].on("track_subscribed")
            def subscribed(track, publication, participant):
                kind = "audio" if track.kind == rtc.TrackKind.KIND_AUDIO else "video"
                tasks.append(asyncio.create_task(consume(track, kind)))

            for room, token in zip(rooms, data["tokens"]):
                # The harness owns this loopback transport. Token issuance,
                # signature, permissions and durable roster use production HTTP.
                await room.connect(f'ws://127.0.0.1:{data["port"]}', token,
                                   options=rtc.RoomOptions(e2ee=rtc.E2EEOptions()))
                for binding in data["frame_keys"]:
                    encoded = binding["key"]
                    key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
                    assert len(key) == 32
                    room.e2ee_manager.key_provider.set_key(binding["participant_id"], key, 0)
                room.e2ee_manager.set_enabled(True)
            sources = [rtc.AudioSource(48000, 1), rtc.AudioSource(48000, 1)]
            videos = [rtc.VideoSource(160, 90), rtc.VideoSource(160, 90)]
            for room, audio, video in zip(rooms, sources, videos):
                audio_publication = await room.local_participant.publish_track(
                    rtc.LocalAudioTrack.create_audio_track("audio", audio),
                    rtc.TrackPublishOptions(source=rtc.TrackSource.SOURCE_MICROPHONE),
                )
                video_publication = await room.local_participant.publish_track(
                    rtc.LocalVideoTrack.create_video_track("video", video),
                    rtc.TrackPublishOptions(source=rtc.TrackSource.SOURCE_CAMERA),
                )

                assert audio_publication.encryption_type == rtc.EncryptionType.GCM
                assert video_publication.encryption_type == rtc.EncryptionType.GCM

            async def publish():
                samples = struct.pack("<480h", *(int(2000 * math.sin(i * 2 * math.pi / 48)) for i in range(480)))
                image = rtc.VideoFrame(160, 90, rtc.VideoBufferType.RGB24, bytes([30, 80, 130]) * (160 * 90))
                tick = 0
                while True:
                    for source in sources:
                        await source.capture_frame(rtc.AudioFrame(samples, 48000, 1, 480))
                    if tick % 10 == 0:
                        for source in videos:
                            source.capture_frame(image)
                    tick += 1
                    await asyncio.sleep(0.01)

            tasks.append(asyncio.create_task(publish()))
            for _ in range(300):
                if frames["audio"] > 2 and frames["video"] > 2:
                    break
                await asyncio.sleep(0.05)
            else:
                raise RuntimeError("actual audio/video frames did not reach the subscriber")
            print(json.dumps({"phase": "connected", "actual_audio_video_frames": True, "encrypted_publishers": 2}), flush=True)
            command = json.loads(await asyncio.to_thread(sys.stdin.readline))
            assert command == {"phase": "consent_revoked"}
            before = dict(frames)
            await asyncio.sleep(0.7)
            assert all(frames[kind] > before[kind] for kind in frames), "Consent revoke hung up an established media session"
            assert all(room.connection_state == rtc.ConnectionState.CONN_CONNECTED for room in rooms)
            print(json.dumps({"phase": "complete", "media_survived_revoke": True}), flush=True)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for room in rooms:
                await room.disconnect()
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(run(json.loads(sys.stdin.readline())), timeout=60))
