"""Bounded startup hot-DLL capture for a selected Frida device."""
import argparse
import json
import time
import threading
from pathlib import Path
import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', required=True)
    parser.add_argument('--pkg', required=True)
    parser.add_argument('--attach', type=int, help='attach to an already running process instead of spawn')
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--seconds', type=int, default=25)
    parser.add_argument('--path', choices=['all', 'files', 'native', 'managed'], default='all')
    parser.add_argument('--late-start', type=int, default=0,
                        help='resume a minimal script first, then load the full agent after this many seconds')
    args = parser.parse_args()
    if args.seconds <= 0 or args.late_start < 0 or args.late_start >= args.seconds:
        parser.error('--seconds must be positive and greater than --late-start')
    harness = run.Harness(str(args.out))
    device = run.get_device(args.device)
    if args.attach:
        pid = args.attach
        session = device.attach(pid)
    else:
        pid = device.spawn([args.pkg])
        session = device.attach(pid)
    started = time.monotonic()
    deadline = started + args.seconds
    result = None
    error = None
    done = threading.Event()
    detached = threading.Event()
    session.on('detached', lambda *unused: detached.set())
    try:
        if args.late_start and not args.attach:
            minimal = session.create_script("rpc.exports = { ping: function () { return 'ready'; } };")
            minimal.load()
            device.resume(pid)
            time.sleep(args.late_start)
            minimal.unload()
        script = session.create_script(run.load_agent())
        script.on('message', harness.on_message)
        script.load()
        if not args.attach and not args.late_start:
            device.resume(pid)
        def install():
            nonlocal result, error
            try:
                if args.path == 'files':
                    result = script.exports_sync.hotfiles()
                elif args.path == 'native':
                    result = script.exports_sync.hotnative({})
                elif args.path == 'managed':
                    result = script.exports_sync.hotmanaged({})
                else:
                    result = script.exports_sync.capturehot({})
                print('Capture hooks:', result, flush=True)
                if args.path in ('managed', 'native', 'files') and not result:
                    error = 'No hooks installed; domain readiness alone does not establish target-method availability'
            except Exception as exc:
                error = str(exc)
            finally:
                done.set()
        threading.Thread(target=install, daemon=True).start()
        while time.monotonic() < deadline and not detached.is_set():
            if done.is_set() and error:
                break
            time.sleep(0.2)
        if not done.is_set():
            error = 'Hook installation did not finish within the total test window'
        elif detached.is_set():
            error = error or 'Session detached during capture'
    except Exception as exc:
        error = str(exc)
    finally:
        dlls = [str(p) for p in args.out.glob('*.dll')]
        report = {'pid': pid, 'device': args.device, 'seconds': args.seconds,
                  'elapsed': round(time.monotonic() - started, 2), 'path': args.path,
                  'late_start': args.late_start, 'installation_finished': done.is_set(),
                  'hook_result': result, 'error': error, 'dlls': dlls,
                  'note': 'No DLL is inconclusive; an installation timeout is not a completed capture window.'}
        (args.out / 'capture-report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        print('Captured DLLs:', len(dlls), 'Error:', error, flush=True)
        session.detach()
    return 2 if error else 0


if __name__ == '__main__':
    run.configure_output()
    raise SystemExit(main())
