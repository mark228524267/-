# PartPay

Сайт со счетами в партрублях: регистрация, вход, переводы по имени и фамилии, админ-панель.
Один файл `main.ts` (Deno), база данных Deno KV. Пароль админа задаётся переменной окружения `ADMIN_PASSWORD`.

- `/` — сайт для пользователей
- `/admin` — админ-панель (вход по паролю `ADMIN_PASSWORD`)

Запуск локально (по желанию): `ADMIN_PASSWORD=секрет deno run -A --unstable-kv main.ts`

## Письма с кодом (EmailJS)
Переменные окружения: `ADMIN_PASSWORD`, `EMAILJS_SERVICE_ID`, `EMAILJS_TEMPLATE_ID`, `EMAILJS_PUBLIC_KEY`, `EMAILJS_PRIVATE_KEY`.
В шаблоне EmailJS используйте параметры `{{to_email}}`, `{{name}}`, `{{code}}`.
