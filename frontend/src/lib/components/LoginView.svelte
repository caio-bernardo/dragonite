<script lang="ts">
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { toaster } from '$lib/stores/toaster';
	import { createClient } from 'matrix-js-sdk';

	let homeserver = $state('https://matrix.org');
	let useremail = $state('');
	let userpassword = $state('');

	async function handleLogin(event: Event) {
		event.preventDefault();
		console.log(homeserver);
		try {
			const client = createClient({ baseUrl: homeserver });

			const response = await client.loginRequest({
				type: 'm.login.password',
				identifier: { type: 'm.id.user', user: useremail },
				password: userpassword
			});

			if (response.access_token && response.user_id && response.device_id) {
				localStorage.setItem('matrix_access_token', response.access_token);
				localStorage.setItem('matrix_user_id', response.user_id);
				localStorage.setItem('matrix_device_id', response.device_id);
				localStorage.setItem('matrix_homeserver', homeserver);
			} else {
				throw new Error('Invalid response from homeserver');
			}

			// redirect to dashboard if login successful
			await goto(resolve('/'));
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} catch (err: any) {
			console.error(err);
			toaster.error({ title: 'Failed to Login', description: err.message });
		}
	}
</script>

<form onsubmit={handleLogin} class="mx-auto w-full max-w-sm space-y-4 rounded-xl border-2 p-6">
	<fieldset class="space-y-4">
		<legend class="text-2xl font-bold">Sign In</legend>

		<label class="label">
			<span class="label-text">Host Server</span>
			<input
				name="host"
				type="text"
				class="input"
				placeholder="matrix.org"
				bind:value={homeserver}
			/>
		</label>

		<label class="label">
			<span class="label-text">Email</span>
			<input
				name="email"
				type="email"
				class="input"
				bind:value={useremail}
				placeholder="user@email.com"
			/>
		</label>

		<label class="label">
			<span class="label-text">Password</span>
			<input
				name="password"
				class="input"
				type="password"
				bind:value={userpassword}
				placeholder="Password"
			/>
		</label>
	</fieldset>
	<fieldset class="flex justify-end">
		<button type="submit" class="btn preset-filled-primary-500">Log in</button>
	</fieldset>
</form>

<style>
	legend {
		margin-left: calc(50% - 35px - 8px);
	}
</style>
