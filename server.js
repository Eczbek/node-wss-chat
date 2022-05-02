
import Database from 'better-sqlite3';
import { readFile } from 'fs/promises';
import { createReadStream } from 'fs';
import { createServer } from 'https';
import { randomUUID } from 'crypto';
import { compare, hash } from 'bcrypt';
import { WebSocketServer } from 'ws';


const database = Database('./database.sqlite');
database.prepare('CREATE TABLE IF NOT EXISTS Users (username TEXT, password TEXT)').run();

const cert = await readFile('./cert.pem');

const sockets = new Map();
const users = new Map();

new WebSocketServer({ server: createServer({
	cert,
	key: cert
}, (_, response) => createReadStream('./client.html').pipe(response)).listen(8230) }).on('connection', (socket) => {
	const socketId = randomUUID();
	let socketName;
	sockets.set(socketId, socket);

	const send = (type, message = {}) => socket.send(JSON.stringify({ ...message, type }));

	socket.on('close', () => {
		sockets.delete(socketId);
		users.delete(socketName);
	});

	socket.on('message', async (buffer) => {
		try {
			const { type, username, password, message, recipients } = JSON.parse(buffer);

			switch (type) {
				case 'login':
					if (socketName) {
						send('login', { error: 'Already logged in' });
						break;
					}
					if (!username) {
						send('login', { error: 'Username required' });
						break;
					}
					if (!password) {
						send('login', { error: 'Password required' });
						break;
					}
					if (!await compare(password, database.prepare('SELECT password FROM Users WHERE username = ?').pluck().get(username) ?? '')) {
						send('login', { error: 'Invalid username or password' });
						break;
					}
					users.set(username, socketId);
					socketName = username;
					send('login', { username });
					break;

				case 'logout':
					if (!socketName) {
						send('logout', { error: 'Not logged in' });
						break;
					}
					users.delete(socketName);
					socketName = undefined;
					send('logout', { username });
					break;

				case 'create':
					if (!username) {
						send('create', { error: 'Username required' });
						break;
					}
					if (database.prepare('SELECT * FROM Users WHERE username = ?').get(username)) {
						send('create', { error: 'Username taken' });
						break;
					}
					if (!password) {
						send('create', { error: 'Password required' });
						break;
					}
					database.prepare('INSERT INTO Users (username, password) VALUES (?, ?)').run(username, await hash(password, 10));
					send('create', { username });
					socket.emit('message', JSON.stringify({
						type: 'login',
						username,
						password
					}));
					break;

				case 'remove':
					if (!username) {
						send('remove', { error: 'Username required' });
						break;
					}
					if (!password) {
						send('remove', { error: 'Password required' });
						break;
					}
					if (!await compare(password, database.prepare('SELECT password FROM Users WHERE username = ?').pluck().get(username) ?? '')) {
						send('remove', { error: 'Invalid username or password' });
						break;
					}
					database.prepare('DELETE FROM Users WHERE username = ?').run(username);
					send('remove', { username });
					socket.emit('message', JSON.stringify({ type: 'logout' }));
					break;

				case 'message':
					if (!socketName) {
						send('message', { error: 'Not logged in' });
						break;
					}
					if (!message) {
						send('message', { error: 'Message required' });
						break;
					}
					{
						const data = JSON.stringify({
							type: 'message',
							message,
							sender: socketName
						});
						[...users].forEach(([_, socketId]) => sockets.get(socketId)?.send(data));
					}
					break;

				case 'whisper':
					if (!socketName) {
						send('whisper', { error: 'Not logged in' });
						break;
					}
					if (!message) {
						send('whisper', { error: 'Message required' });
						break;
					}
					if (!recipients?.length) {
						send('whisper', { error: 'Recipients required' });
						break;
					}
					{
						const data = JSON.stringify({
							type: 'whisper',
							message,
							sender: socketName
						});
						new Set([...recipients, socketName]).forEach((username) => sockets.get(users.get(username))?.send(data));
					}
					break;

				default:
					send('error', { error: 'Invalid message type' });
			}
		} catch (error) {
			console.log(error);
		}
	});
});
