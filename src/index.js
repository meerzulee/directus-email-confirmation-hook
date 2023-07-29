import jwt from "jsonwebtoken";
import { Url } from "@directus/api/utils/url";
import { createError } from "@directus/errors";

const InvalidCredentialsException = (message) => {
  new createError("InvalidCredentialsException", message, 500);
};

export default ({ filter, action }, { services, exceptions, env }) => {
  const { AuthenticationService, MailService } = services;

  filter(
    "users.create",
    async (input, { collection }, { database, schema, accountability }) => {
      // Do not change the payload if request comes from app / admin
      if (!accountability || (accountability.admin && accountability.app))
        return;
      input.status = "invited";
      // delete input.status;
      // delete input.role;
      return input;
    }
  );
  action("users.create", async ({ payload }, { schema, accountability }) => {
    // Do not send activation email if user is created from app or by admin
    if (!accountability || (accountability.admin && accountability.app)) return;

    const mailService = new MailService({
      accountability,
      schema,
    });

    const { email } = payload;

    const tokenPayload = { email, scope: "invite" };
    const token = jwt.sign(tokenPayload, env.SECRET, {
      expiresIn: "30m",
      issuer: "directus",
    });
    const inviteURL = new Url(env.FRONTEND_URL).addPath("email-confirm");
    inviteURL.setQuery("token", token);

    await mailService.send({
      to: email,
      subject: "Confirm your user account",
      template: {
        name: "user-invitation",
        data: {
          url: inviteURL.toString(),
          email,
        },
      },
    });
  });
};
