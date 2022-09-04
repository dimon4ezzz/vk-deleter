# Удаление из ВКонтакте

Приложение вызывает API удаления вашего контента ВКонтакте. Для работы требуется логин, пароль и [распакованный архив данных ВКонтакте](https://vk.com/data_protection?section=rules&scroll_to_archive=1).

## Запуск процесса

1. поместите `main.go` или `vk-deleter` в папку распакованного архива
   1. если запуск через `main.go`, добавьте данные `client_id` и `client_secret` в нужные константы
1. запустите `go run main.go` или `vk-deleter`
1. введите логин, пароль и двухфакторный код
1. наблюдайте за консолью, могут вылезти ошибки

## Реализованные виды контента

- [x] комментарии
- [ ] записи на стене
