import bcryptjs from "bcryptjs";

/** Reports whether bcrypt would preserve every UTF-8 byte of this password. */
export function bcryptPreserves(password: string) {
  return !bcryptjs.truncates(password);
}
