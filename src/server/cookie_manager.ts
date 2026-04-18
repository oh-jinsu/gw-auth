import {
  parse,
  serialize,
  type ParseOptions,
  type SerializeOptions,
} from "cookie";

export const defaultCookieOptions: SerializeOptions = {
  path: "/",
  httpOnly: process.env.NODE_ENV === "production",
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
};

export class CookieManager {
  name: string;
  options: SerializeOptions;

  constructor(name: string, options: SerializeOptions = defaultCookieOptions) {
    this.name = name;
    this.options = options;
  }

  async parseFromRequest(
    request: Request,
    parseOptions?: ParseOptions | undefined,
  ): Promise<string | undefined> {
    const cookieHeader = request.headers.get("cookie");

    if (!cookieHeader) return undefined;

    return this.parse(cookieHeader, parseOptions);
  }

  async parse(
    cookieHeader: string,
    parseOptions?: ParseOptions | undefined,
  ): Promise<string | undefined> {
    let cookies = parse(cookieHeader, { ...this.options, ...parseOptions });

    if (this.name in cookies) {
      let value = cookies[this.name];
      if (typeof value === "string" && value !== "") {
        return value;
      } else {
        return undefined;
      }
    } else {
      return undefined;
    }
  }

  async serialize(
    value: string | undefined,
    serializeOptions?: SerializeOptions,
  ): Promise<string> {
    return serialize(this.name, value || "", {
      ...this.options,
      maxAge: !value ? 0 : undefined,
      ...serializeOptions,
    });
  }
}

export class SessionCookieManager extends CookieManager {
  serialize(
    value: string | undefined,
    serializeOptions?: SerializeOptions,
  ): Promise<string> {
    return super.serialize(value, {
      ...serializeOptions,
      maxAge: undefined,
      expires: undefined,
    });
  }
}
