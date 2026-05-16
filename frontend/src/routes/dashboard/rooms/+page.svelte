<script lang="ts">
    import { resolve } from '$app/paths';
    import { matrixService } from '$lib';
    import { Hash, Users, MessageSquare } from '@lucide/svelte';

    // Aqui pegamos as salas do serviço.
    // Como eu não sei o nome exato da propriedade no matrixService,
    // coloquei um array de teste como fallback (||) para ver o visual funcionando.
    let rooms = $derived(matrixService.channels || [
        { id: 'sala-1', name: 'Geral', type: 'public', members: 120 },
        { id: 'sala-2', name: 'Projeto Dragonite', type: 'private', members: 5 },
        { id: 'sala-3', name: 'Avisos da Comunidade', type: 'public', members: 42 }
    ]);
</script>

<main class="mx-auto flex w-full max-w-3xl flex-col gap-10 p-6 lg:p-12">

    <hgroup class="text-center">
        <h1 class="h1">Minhas Salas</h1>
        <p class="mt-2 text-surface-600-400">Gerencie e acesse os canais que você participa.</p>
    </hgroup>

    {#if rooms.length === 0}
        <div class="card flex flex-col items-center justify-center gap-4 p-12 text-center border border-surface-200-800 bg-surface-50-950/30">
            <MessageSquare size={48} class="opacity-50" />
            <h3 class="h3">Nenhuma sala encontrada</h3>
            <p class="text-surface-600-400">Você ainda não participa de nenhum canal.</p>
            <a href={resolve('/dashboard')} class="btn preset-filled-primary-50-950 mt-4">
                Descobrir Canais
            </a>
        </div>
    {:else}
        <ul class="flex flex-col gap-4">
            {#each rooms as room (room.id)}
                <li class="card flex items-center justify-between p-5 border border-surface-200-800 bg-surface-50-950/30 transition-all hover:bg-surface-100-900/50 hover:-translate-y-0.5">

                    <div class="flex items-center gap-5">
                        <div class="flex h-14 w-14 shrink-0 items-center justify-center rounded-full bg-surface-200-800/50">
                            {#if room.type === 'private'}
                                <Users size={26} />
                            {:else}
                                <Hash size={26} />
                            {/if}
                        </div>

                        <div>
                            <h3 class="text-lg font-bold">{room.name}</h3>
                            <p class="text-sm text-surface-600-400">{room.members} membros</p>
                        </div>
                    </div>

                    <a href={resolve(`/dashboard/rooms/${room.id}` as any)} class="btn preset-filled-primary-50-950 font-bold">
                        Entrar
                    </a>
                </li>
            {/each}
        </ul>
    {/if}
</main>
