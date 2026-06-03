// Firebase отключён для деплоя — логи хранятся в памяти сервера
const db = {
    collection: () => ({
        add: async () => {}
    })
};

module.exports = { db };