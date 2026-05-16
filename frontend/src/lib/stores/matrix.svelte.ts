import { createClient, type MatrixClient } from 'matrix-js-sdk';
import { browser } from '$app/environment';

class MatrixService {
	client: MatrixClient | null = $state(null);
	userProfile = $state({ displayname: '', avatarUrl: '' });

	constructor() {
		if (browser) {
			this.tryResumeSession();
		}
	}

	async tryResumeSession() {
		const token = localStorage.getItem('matrix_access_token');
		const baseUrl = localStorage.getItem('matrix_homeserver');
		const userId = localStorage.getItem('matrix_user_id');

		if (token && baseUrl && userId) {
			await this.startSession(baseUrl, token, userId);
		}
	}

	async startSession(baseUrl: string, accessToken: string, userId: string) {
		this.client = createClient({
			baseUrl,
			accessToken,
			userId
		});

		// vai chamar sync a cada 10 segundos
		await this.client.startClient({ initialSyncLimit: 10 });

		this.fetchProfile();
	}

	async login(baseUrl: string, username: string, password: string) {
		const tempClient = createClient({ baseUrl });
		const response = await tempClient.loginRequest({
			type: 'm.login.password',
			identifier: { type: 'm.id.user', user: username },
			password: password
		});

		localStorage.setItem('matrix_access_token', response.access_token);
		localStorage.setItem('matrix_user_id', response.user_id);
		localStorage.setItem('matrix_device_id', response.device_id);
		localStorage.setItem('matrix_homeserver', baseUrl);

		await this.startSession(baseUrl, response.access_token, response.user_id);
	}

	async register(baseUrl: string, username: string, password: string) {
		const tempClient = createClient({ baseUrl });
		const response = await tempClient.register(username, password, null, {
			type: 'm.login.password'
		});

		if (response.access_token && response.user_id && response.device_id) {
			localStorage.setItem('matrix_access_token', response.access_token);
			localStorage.setItem('matrix_user_id', response.user_id);
			localStorage.setItem('matrix_device_id', response.device_id);
			localStorage.setItem('matrix_homeserver', baseUrl);
			await this.startSession(baseUrl, response.access_token, response.user_id);
		} else {
			await this.login(baseUrl, username, password);
		}
	}

	logout() {
		if (this.client) this.client.stopClient();
		localStorage.clear();
		this.client = null;
	}

	async fetchProfile() {
		const info = await this.client?.getProfileInfo(this.client?.getUserId() ?? 'unknown');
		this.userProfile = {
			displayname: info?.displayname ?? '',
			avatarUrl: info?.avatar_url ?? ''
		};
	}

	async searchUsers(term: string) {
  	if (!this.client) return [];
		const client = this.client;
 		const response = await client.searchUserDirectory({ term, limit: 10 });
 		
		return response.results.map((user) => ({
   			userId: user.user_id,
   			displayName: user.display_name ?? user.user_id,
   			avatarUrl: user.avatar_url ? (client.mxcUrlToHttp(user.avatar_url) ?? '') : ''
  		}));
  }
  
	async updateProfile(props: { displayname: string }) {
		await this.client?.setDisplayName(props.displayname);
	}

	async uploadAvatar(file: File) {
		if (!this.client) throw Error('Client not initialized');
		const { content_uri } = await this.client.uploadContent(file, {
			name: file.name,
			type: file.type
		});
		await this.client.setAvatarUrl(content_uri);
		return content_uri;
	}

	isAuthenticated() {
		return this.client !== null;
	}

	getUserID() {
		return this.client?.getUserId() ?? '';
	}
}

export const matrixService = new MatrixService();
