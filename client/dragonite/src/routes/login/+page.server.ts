import type { Actions } from './$types';

export const actions = {
	// TODO: Log the user
	default: async (event) => {
		const data = await event.request.formData();
		console.log(data);
	}
} satisfies Actions;
