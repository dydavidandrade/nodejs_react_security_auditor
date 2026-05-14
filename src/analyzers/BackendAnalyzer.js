import path from 'path';
import BaseAnalyzer from './BaseAnalyzer.js';
import { Finding } from '../utils/Finding.js';

const ROUTE_DECORATORS = /@(Get|Post|Put|Delete|Patch|Options|Head|All)\s*\(/g;

class BackendAnalyzer extends BaseAnalyzer {
  constructor(rootDir, fileSystem, logger) {
    super(rootDir, fileSystem, logger);
    this.framework = null;
    this.routes = [];
  }

  async analyze() {
    const pkg = this.fs.readJson(this.fs.join(this.rootDir, 'package.json'));
    if (!pkg) return;

    this._detectFramework(pkg);
    const jsFiles = this.fs.getAllFiles(['.js', '.ts', '.mjs', '.cjs']);

    for (const file of jsFiles) {
      const content = this.fs.readFile(file);
      if (!content) continue;
      this._checkHelmet(content, file);
      this._checkCors(content, file);
      this._checkRateLimit(content, file);
      this._checkJwt(content, file);
      this._checkPasswordHashing(content, file);
      this._checkSqlConcatenation(content, file);
      this._checkEval(content, file);
      this._checkHardcodedSecrets(content, file);
      this._checkErrorLeakage(content, file);
      this._extractAndCheckRoutes(content, file);
    }
  }

  _detectFramework(pkg) {
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (deps['@nestjs/core'] || deps['@nestjs/common']) {
      this.framework = 'nestjs';
      this.logger.info('Framework detectado: NestJS');
    } else if (deps['express']) {
      this.framework = 'express';
      this.logger.info('Framework detectado: Express.js');
    } else {
      this.logger.info('Framework backend: no identificado');
    }
  }

  _checkHelmet(content, file) {
    if (!this._hasPattern(content, 'helmet')) {
      if (/app\.(js|ts)$|server\.(js|ts)$|main\.(js|ts)$/.test(file)) {
        this.addFinding(new Finding({
          title: 'Helmet middleware no configurado',
          control_id: 'BACKEND-03', asvs_id: 'ASVS 14.4.1', severity: 'high', category: 'backend',
          description: 'El archivo principal no usa helmet(), dejando la aplicación sin cabeceras de seguridad HTTP.',
          remediation_steps: 'Instala y configura helmet: `npm install helmet` y agrega `app.use(helmet())` antes de tus rutas. Configura CSP, HSTS, X-Frame-Options y demás cabeceras de seguridad.',
          file: this.fs.relative(file), evidence_uri: this.fs.relative(file),
        }));
      }
    }
  }

  _checkCors(content, file) {
    if (this._hasPattern(content, 'origin\\s*:\\s*[\'"`]\\*[\'"`]')) {
      const idx = content.search(/origin\s*:\s*['"`]\*['"`]/);
      this.addFinding(new Finding({
        title: 'CORS con wildcard origin (*)',
        control_id: 'BACKEND-07', asvs_id: 'ASVS 14.4.8', severity: 'high', category: 'backend',
        description: 'CORS configurado con origin:\'*\' permite peticiones desde cualquier dominio.',
        remediation_steps: 'Reemplaza `origin: \'*\'` con una lista blanca de dominios permitidos: `origin: [\'https://tudominio.com\']`.',
        file: this.fs.relative(file), line: this._lineOf(content, idx), evidence_uri: this.fs.relative(file),
      }));
    }
  }

  _checkRateLimit(content, file) {
    if (/app\.(js|ts)$|server\.(js|ts)$|main\.(js|ts)$/.test(file) && !this._hasPattern(content, 'rate.?limit|rateLimit|throttle')) {
      this.addFinding(new Finding({
        title: 'Rate limiting no configurado',
        control_id: 'BACKEND-08', asvs_id: 'ASVS 4.2.2', severity: 'high', category: 'backend',
        description: 'La aplicación no implementa rate limiting, vulnerable a brute force y DoS.',
        remediation_steps: 'Instala `express-rate-limit` o `@nestjs/throttler` y configúralo globalmente. Ejemplo: máximo 100 requests por 15 minutos por IP.',
        file: this.fs.relative(file), evidence_uri: this.fs.relative(file),
      }));
    }
  }

  _checkJwt(content, file) {
    const weakSecrets = [/secret\s*:\s*['"`](secret|password|123|jwt|token|key)['"`]/i, /jwt\.sign\([^,]+,\s*['"`](secret|password|123)['"`]/i];
    for (const re of weakSecrets) {
      if (re.test(content)) {
        this.addFinding(new Finding({
          title: 'JWT con secreto débil hardcodeado',
          control_id: 'AUTH-04', asvs_id: 'ASVS 3.5.3', severity: 'critical', category: 'authentication',
          description: 'Se detectó un secreto JWT débil o hardcodeado en el código fuente.',
          remediation_steps: 'Usa un secreto de mínimo 256 bits aleatorios desde variables de entorno: `process.env.JWT_SECRET`. Nunca hardcodees secretos criptográficos.',
          file: this.fs.relative(file), line: this._lineOf(content, content.search(re)), evidence_uri: this.fs.relative(file),
        }));
      }
    }
    if (this._hasPattern(content, 'jwt\\.sign') && !this._hasPattern(content, 'expiresIn|exp\\s*:')) {
      this.addFinding(new Finding({
        title: 'JWT sin expiración configurada',
        control_id: 'AUTH-04', asvs_id: 'ASVS 3.5.1', severity: 'critical', category: 'authentication',
        description: 'Tokens JWT generados sin campo de expiración (exp), válidos indefinidamente.',
        remediation_steps: 'Agrega `expiresIn: \'15m\'` a jwt.sign(). Implementa refresh tokens y blacklist en Redis.',
        file: this.fs.relative(file), evidence_uri: this.fs.relative(file),
      }));
    }
  }

  _checkPasswordHashing(content, file) {
    if (this._hasPattern(content, 'password|passwd|contraseña', 'i') && !this._hasPattern(content, 'argon2|bcrypt') && this._hasPattern(content, 'sha[0-9]|md5|createHash')) {
      const idx = content.search(/sha[0-9]|md5|createHash/i);
      this.addFinding(new Finding({
        title: 'Hash de contraseñas con algoritmo inseguro (MD5/SHA)',
        control_id: 'AUTH-02', asvs_id: 'ASVS 2.4.1', severity: 'critical', category: 'authentication',
        description: 'Se usa MD5 o SHA para hashear contraseñas. Estos algoritmos son inseguros para passwords.',
        remediation_steps: 'Reemplaza con argon2id: `npm install argon2` y usa `argon2.hash(password)`. Si usas bcrypt, asegúrate de un cost factor ≥ 12.',
        file: this.fs.relative(file), line: this._lineOf(content, idx), evidence_uri: this.fs.relative(file),
      }));
    }
  }

  _checkSqlConcatenation(content, file) {
    const patterns = [
      /query\s*\(\s*['"`][^'"`]*\+\s*(?:req\.|params\.|body\.|query\.)/,
      /execute\s*\(\s*`[^`]*\$\{(?:req\.|params\.|body\.|query\.)/,
      /SELECT[^'"]*\+\s*(?:req\.|params\.|body\.|query\.)/i,
    ];
    for (const re of patterns) {
      if (re.test(content)) {
        this.addFinding(new Finding({
          title: 'Posible SQL Injection — Query concatenada con input de usuario',
          control_id: 'BACKEND-02', asvs_id: 'ASVS 5.3.4', severity: 'critical', category: 'injection',
          description: 'Se detectó concatenación directa de input del usuario en queries SQL.',
          remediation_steps: 'Usa siempre prepared statements o parameterized queries. Con Knex: `knex(\'users\').where(\'id\', userId)`. Con TypeORM: `repo.findOne({ where: { id } })`.',
          file: this.fs.relative(file), line: this._lineOf(content, content.search(re)), evidence_uri: this.fs.relative(file),
        }));
        break;
      }
    }
  }

  _checkEval(content, file) {
    const re = /\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`]/;
    if (re.test(content)) {
      this.addFinding(new Finding({
        title: 'Uso de eval() — potencial RCE',
        control_id: 'BACKEND-04', asvs_id: 'ASVS 5.2.4', severity: 'critical', category: 'rce',
        description: 'Se detectó eval() o new Function() que puede ejecutar código arbitrario.',
        remediation_steps: 'Elimina eval(), new Function() y setTimeout/setInterval con strings.',
        file: this.fs.relative(file), line: this._lineOf(content, content.search(re)), evidence_uri: this.fs.relative(file),
      }));
    }
  }

  _checkHardcodedSecrets(content, file) {
    const patterns = [
      { re: /(?:password|passwd|secret|apikey|api_key|token|private_key)\s*[=:]\s*['"`]([^'"`]{8,})['"`]/i, label: 'credencial hardcodeada' },
      { re: /sk-[a-zA-Z0-9]{20,}/, label: 'OpenAI API key' },
      { re: /AKIA[0-9A-Z]{16}/, label: 'AWS Access Key' },
      { re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, label: 'clave privada embebida' },
      { re: /mongodb\+srv:\/\/[^:]+:[^@]+@/, label: 'MongoDB connection string con credenciales' },
    ];
    for (const { re, label } of patterns) {
      if (re.test(content)) {
        this.addFinding(new Finding({
          title: `Secreto hardcodeado detectado: ${label}`,
          control_id: 'CRYPTO-04', asvs_id: 'ASVS 6.4.1', severity: 'critical', category: 'secrets',
          description: `Se encontró un ${label} directamente en el código fuente.`,
          remediation_steps: 'Mueve todos los secretos a variables de entorno (.env) y usa un Secret Manager. Rota todas las credenciales comprometidas inmediatamente.',
          file: this.fs.relative(file), line: this._lineOf(content, content.search(re)), evidence_uri: this.fs.relative(file),
        }));
        break;
      }
    }
  }

  _checkErrorLeakage(content, file) {
    const re = /res\.(?:status\([^)]+\)\.)?(?:send|json)\s*\(\s*err(?:or)?\s*\)|res\.(?:send|json)\s*\(\s*\{\s*(?:error|message|stack)\s*:\s*err/;
    if (re.test(content)) {
      this.addFinding(new Finding({
        title: 'Exposición de errores internos al cliente',
        control_id: 'BACKEND-06', asvs_id: 'ASVS 7.4.1', severity: 'medium', category: 'information_disclosure',
        description: 'El stack trace o mensajes de error internos se envían directamente al cliente.',
        remediation_steps: 'Implementa un handler de errores global que retorne mensajes genéricos en producción: `{ error: "Internal server error" }`.',
        file: this.fs.relative(file), line: this._lineOf(content, content.search(re)), evidence_uri: this.fs.relative(file),
      }));
    }
  }

  _extractAndCheckRoutes(content, file) {
    if (!/routes?\.(js|ts)$|controller\.(js|ts)$/.test(file) && !this._hasPattern(content, '@Controller|router\\.')) return;
    let m;
    const re = new RegExp(ROUTE_DECORATORS.source, 'g');
    while ((m = re.exec(content)) !== null) {
      const snippet = content.substring(m.index, m.index + 300);
      if (!this._hasPattern(snippet, 'UsePipes|ValidationPipe|@Body|ParseInt|IsString|IsEmail|Dto')) {
        this.routes.push({ file: this.fs.relative(file), decorator: m[0], line: this._lineOf(content, m.index) });
        this.addFinding(new Finding({
          title: `Ruta sin validación de entrada: ${m[0]}`,
          control_id: 'BACKEND-01', asvs_id: 'ASVS 5.1.3', severity: 'high', category: 'validation',
          description: `El endpoint ${m[0]} en ${path.basename(file)} no tiene ValidationPipe o DTO con class-validator.`,
          remediation_steps: 'Agrega @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })) al controlador. Define DTOs con decoradores de class-validator.',
          file: this.fs.relative(file), line: this._lineOf(content, m.index), evidence_uri: this.fs.relative(file),
        }));
      }
    }
  }
}

export default BackendAnalyzer;
