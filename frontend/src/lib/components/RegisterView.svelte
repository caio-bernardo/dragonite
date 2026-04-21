<script lang="ts">
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { toaster } from '$lib/stores/toaster';
	import { createClient } from 'matrix-js-sdk';

	const homeserver = 'http://localhost:8080';
	let username = $state('');
	let userpassword = $state('');
	let confirmpassword = $state('');

	async function handleRegister(event: Event) {
		event.preventDefault();

		// Form validation
		if (username.trim().length === 0) {
			toaster.error({
				title: 'Username Required',
				description: 'Please enter a username.'
			});
			return;
		}
		if (!username.match(/^[\w\d._=+-]+$/)) {
			toaster.error({
				title: 'Invalid Username',
				description: 'Username should just contain letters, digits or .,_,=,+,-'
			});
			return;
		}

		if (userpassword.trim().length < 6) {
			toaster.error({
				title: 'Password Too Short',
				description: 'Your password must be at least 6 characters long.'
			});
			return;
		}

		if (userpassword !== confirmpassword) {
			toaster.error({
				title: 'Password Mismatch',
				description: 'The passwords you entered do not match.'
			});
			return;
		}

		try {
			const client = createClient({ baseUrl: homeserver });

			const response = await client.register(username, userpassword, null, {
				type: 'm.login.password'
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

<form onsubmit={handleRegister} class="mx-auto w-full max-w-sm space-y-4 rounded-xl border-2 p-6">
	<fieldset class="space-y-4">
		<legend class="text-2xl font-bold">Sign Up</legend>

		<label class="label">
			<span class="label-text">Username</span>
			<input
				name="username"
				type="text"
				class="input"
				bind:value={username}
				placeholder="ex.: joao67"
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

		<label class="label">
			<span class="label-text">Confirm password</span>
			<input
				name="password"
				class="input"
				type="password"
				bind:value={confirmpassword}
				placeholder="Password"
			/>
		</label>
	</fieldset>
	<fieldset class="flex justify-end">
		<button type="submit" class="btn preset-filled-primary-500">Create</button>
	</fieldset>
</form>

<style>
	legend {
		margin-left: calc(50% - 35px - 8px);
	}
</style>
