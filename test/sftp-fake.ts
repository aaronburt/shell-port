import fs from "node:fs";
import path from "node:path";
import ssh2 from "ssh2";

const { STATUS_CODE } = ssh2.utils.sftp;

export function serveSftp(root: string, accept: () => any) {
  const sftp = accept();
  const handles = new Map<string, { kind: "dir"; list: string[]; sent: boolean; dir: string } | { kind: "file"; fd: number }>();
  let n = 0;
  const real = (p: string) => path.join(root, path.posix.normalize("/" + p));
  const attrsOf = (st: fs.Stats) => ({ mode: st.mode, uid: st.uid, gid: st.gid, size: st.size, atime: Math.floor(st.atimeMs / 1000), mtime: Math.floor(st.mtimeMs / 1000) });
  const status = (reqid: number, e: unknown) => {
    const code = (e as NodeJS.ErrnoException)?.code;
    sftp.status(reqid, code === "ENOENT" ? STATUS_CODE.NO_SUCH_FILE : code === "EACCES" || code === "EPERM" ? STATUS_CODE.PERMISSION_DENIED : STATUS_CODE.FAILURE);
  };
  const newHandle = (h: any) => {
    const id = Buffer.from(String(++n));
    handles.set(id.toString(), h);
    return id;
  };

  sftp.on("REALPATH", (reqid: number, p: string) => {
    const logical = path.posix.normalize(p === "." ? "/home/demo" : p.startsWith("/") ? p : "/home/demo/" + p);
    sftp.name(reqid, [{ filename: logical, longname: logical, attrs: {} }]);
  });
  sftp.on("OPENDIR", (reqid: number, p: string) => {
    try {
      const dir = real(p);
      sftp.handle(reqid, newHandle({ kind: "dir", list: fs.readdirSync(dir), sent: false, dir }));
    } catch (e) { status(reqid, e); }
  });
  sftp.on("READDIR", (reqid: number, h: Buffer) => {
    const x = handles.get(h.toString());
    if (!x || x.kind !== "dir" || x.sent) return sftp.status(reqid, STATUS_CODE.EOF);
    x.sent = true;
    const names = [".", "..", ...x.list];
    sftp.name(reqid, names.map((filename) => {
      const st = fs.lstatSync(path.join(x.dir, filename));
      return { filename, longname: filename, attrs: attrsOf(st) };
    }));
  });
  const stat = (follow: boolean) => (reqid: number, p: string) => {
    try { sftp.attrs(reqid, attrsOf(follow ? fs.statSync(real(p)) : fs.lstatSync(real(p)))); } catch (e) { status(reqid, e); }
  };
  sftp.on("STAT", stat(true));
  sftp.on("LSTAT", stat(false));
  sftp.on("OPEN", (reqid: number, p: string) => {
    try { sftp.handle(reqid, newHandle({ kind: "file", fd: fs.openSync(real(p), "r") })); } catch (e) { status(reqid, e); }
  });
  sftp.on("FSTAT", (reqid: number, h: Buffer) => {
    const x = handles.get(h.toString());
    if (x?.kind === "file") sftp.attrs(reqid, attrsOf(fs.fstatSync(x.fd)));
    else sftp.status(reqid, STATUS_CODE.FAILURE);
  });
  sftp.on("READ", (reqid: number, h: Buffer, offset: number, length: number) => {
    const x = handles.get(h.toString());
    if (x?.kind !== "file") return sftp.status(reqid, STATUS_CODE.FAILURE);
    const buf = Buffer.alloc(length);
    const got = fs.readSync(x.fd, buf, 0, length, offset);
    got ? sftp.data(reqid, buf.subarray(0, got)) : sftp.status(reqid, STATUS_CODE.EOF);
  });
  sftp.on("CLOSE", (reqid: number, h: Buffer) => {
    const x = handles.get(h.toString());
    if (x?.kind === "file") fs.closeSync(x.fd);
    handles.delete(h.toString());
    sftp.status(reqid, STATUS_CODE.OK);
  });
  sftp.on("REMOVE", (reqid: number, p: string) => {
    try { fs.unlinkSync(real(p)); sftp.status(reqid, STATUS_CODE.OK); } catch (e) { status(reqid, e); }
  });
  sftp.on("RMDIR", (reqid: number, p: string) => {
    try { fs.rmdirSync(real(p)); sftp.status(reqid, STATUS_CODE.OK); } catch (e) { status(reqid, e); }
  });
}
