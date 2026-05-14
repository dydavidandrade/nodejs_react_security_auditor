import inquirer from "inquirer";
import { t, setLang } from "./i18n.js";

const prompt = inquirer.createPromptModule();

class Prompt {
  async selectLanguage() {
    const { lang } = await prompt([
      {
        type: "list",
        name: "lang",
        message: "Select report language / Selecciona el idioma del reporte:",
        choices: [
          { name: "Español", value: "es" },
          { name: "English", value: "en" },
        ],
        default: "es",
      },
    ]);
    setLang(lang);
    return lang;
  }

  async getAuthConfig() {
    const { needsAuth } = await prompt([
      {
        type: "confirm",
        name: "needsAuth",
        message: t("auth_question"),
        default: false,
      },
    ]);

    if (!needsAuth) return { enabled: false };

    const { authType } = await prompt([
      {
        type: "list",
        name: "authType",
        message: "Authentication type (login | token ):",
        choices: [
          { name: "Username + Password (login endpoint)", value: "login" },
          { name: "Static token / API key", value: "token" },
        ],
      },
    ]);

    if (authType === "token") {
      const { header, value } = await prompt([
        {
          type: "input",
          name: "header",
          message: t("auth_token_header"),
          default: "Authorization",
        },
        {
          type: "password",
          name: "value",
          message: t("auth_token_value"),
          mask: "*",
        },
      ]);
      return { enabled: true, type: "token", header, value };
    }

    const {
      loginUrl,
      username,
      password: pwd,
    } = await prompt([
      { type: "input", name: "loginUrl", message: t("auth_url") },
      { type: "input", name: "username", message: t("auth_user") },
      {
        type: "password",
        name: "password",
        message: t("auth_pass"),
        mask: "*",
      },
    ]);
    return { enabled: true, type: "login", loginUrl, username, password: pwd };
  }

  async confirmStart(url) {
    const { ok } = await prompt([
      {
        type: "confirm",
        name: "ok",
        message: t("confirm_start", { url }),
        default: true,
      },
    ]);
    return ok;
  }
}

export default Prompt;
