<script lang="ts">
    import { onMount, onDestroy } from 'svelte';
    import { SendHorizonal, Loader, ArrowLeft } from '@lucide/svelte';
    import { matrixService } from '$lib';
    import { goto } from '$app/navigation';
    import 'emoji-picker-element';

    let { data } = $props();
    // $derived garante reatividade se data mudar (ex: navegação entre salas)
    let roomId = $derived(data.roomId);
    const myUserId = matrixService.getUserID();

    let isReady = $derived(
        matrixService.syncState === 'PREPARED' ||
        matrixService.syncState === 'SYNCING' ||
        matrixService.syncState === 'CATCHUP'
    );

    let messageVersion = $state(0);
    let messages = $derived.by(() => {
        messageVersion;
        return matrixService.getRoomMessages(roomId);
    });
    let roomName = $derived(matrixService.getRoomName(roomId));

    let currentMessage = $state('');
    let isSending = $state(false);
    let elemChat = $state<HTMLElement | undefined>(undefined);

    // --- Emoji picker ---
    let showEmojiPicker = $state(false);
    let pickerContainer = $state<HTMLDivElement | undefined>(undefined);
    let emojiPickerEl = $state<HTMLElement | undefined>(undefined);

    function onEmojiSelect(e: Event) {
        currentMessage += (e as CustomEvent).detail.unicode;
        showEmojiPicker = false;
    }

    function onClickOutside(e: MouseEvent) {
        if (showEmojiPicker && !pickerContainer?.contains(e.target as Node)) {
            showEmojiPicker = false;
        }
    }
    // --------------------

    function scrollToBottom(behavior: ScrollBehavior = 'smooth') {
        elemChat?.scrollTo({ top: elemChat.scrollHeight, behavior });
    }

    async function sendMessage() {
        const body = currentMessage.trim();
        if (!body || isSending) return;
        isSending = true;
        try {
            await matrixService.sendMessage(roomId, body);
            currentMessage = '';
        } finally {
            isSending = false;
        }
    }

    function onKeydown(e: KeyboardEvent) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    }

    let unsubscribe: () => void;

    onMount(() => {
        scrollToBottom('instant');

        unsubscribe = matrixService.onRoomTimeline(roomId, () => {
            messageVersion++;
            setTimeout(() => scrollToBottom('smooth'), 0);
        });

        document.addEventListener('click', onClickOutside);
    });

    onDestroy(() => {
        unsubscribe?.();
        document.removeEventListener('click', onClickOutside);
        emojiPickerEl?.removeEventListener('emoji-click', onEmojiSelect);
    });

    // Registra o listener no elemento do picker quando ele entrar no DOM
    $effect(() => {
        if (emojiPickerEl) {
            emojiPickerEl.addEventListener('emoji-click', onEmojiSelect);
        }
    });
</script>

<div class="grid h-full grid-rows-[auto_1fr_auto]">

    <!-- Header: nome real da sala -->
    <header class="flex items-center gap-3 border-b border-surface-200-800 px-4 py-3">
        <button
            onclick={() => goto('/dashboard/rooms')}
            class="btn-icon preset-tonal lg:hidden"
            aria-label="Voltar"
        >
            <ArrowLeft size={18} />
        </button>
        <span class="opacity-50">#</span>
        <h2 class="font-bold">{roomName}</h2>
    </header>

    <!-- Feed ou loading -->
    {#if !isReady}
        <div class="flex flex-col items-center justify-center gap-3 opacity-50">
            <Loader size={28} class="animate-spin" />
            <p class="text-sm">Sincronizando mensagens...</p>
        </div>
    {:else}
        <section
            bind:this={elemChat}
            class="overflow-y-auto space-y-4 p-4"
        >
            {#if messages.length === 0}
                <p class="mt-10 text-center opacity-50">Nenhuma mensagem ainda.</p>
            {/if}

            {#each messages as msg (msg.id)}
                {@const isMe = msg.senderId === myUserId}

                {#if isMe}
                    <div class="grid grid-cols-[1fr_auto] gap-2">
                        <div class="card rounded-tr-none space-y-1 p-3 preset-tonal-primary">
                            <header class="flex items-center justify-between gap-4">
                                <p class="text-sm font-bold">{msg.senderName}</p>
                                <small class="shrink-0 opacity-50">{msg.timestamp}</small>
                            </header>
                            <p class="text-sm">{msg.body}</p>
                        </div>
                    </div>
                {:else}
                    <div class="grid grid-cols-[auto_1fr] gap-2">
                        <div class="card rounded-tl-none space-y-1 p-3 preset-tonal">
                            <header class="flex items-center justify-between gap-4">
                                <p class="text-sm font-bold">{msg.senderName}</p>
                                <small class="shrink-0 opacity-50">{msg.timestamp}</small>
                            </header>
                            <p class="text-sm">{msg.body}</p>
                        </div>
                    </div>
                {/if}
            {/each}
        </section>
    {/if}

    <!-- Prompt -->
    <section class="border-t border-surface-200-800 p-4">
        <div class="relative" bind:this={pickerContainer}>

            <!-- Picker flutua acima do input -->
            {#if showEmojiPicker}
                <div class="absolute bottom-full right-0 mb-2 z-50">
                    <emoji-picker
                        class="rounded-container shadow-xl"
                        bind:this={emojiPickerEl}
                    ></emoji-picker>
                </div>
            {/if}

            <!-- Input group: textarea | emoji | enviar -->
            <div class="input-group grid-cols-[1fr_auto_auto] divide-x divide-surface-200-800 rounded-container">
                <textarea
                    bind:value={currentMessage}
                    onkeydown={onKeydown}
                    class="resize-none border-0 bg-transparent ring-0"
                    placeholder="Escreva uma mensagem... (Enter para enviar)"
                    rows="1"
                    disabled={isSending || !isReady}
                ></textarea>

                <!-- Botão emoji -->
                <button
                    type="button"
                    onclick={(e) => { e.stopPropagation(); showEmojiPicker = !showEmojiPicker; }}
                    class="input-group-cell preset-tonal"
                    aria-label="Emojis"
                    disabled={!isReady}
                >
                    😊
                </button>

                <!-- Botão enviar -->
                <button
                    onclick={sendMessage}
                    disabled={!currentMessage.trim() || isSending || !isReady}
                    class="input-group-cell {currentMessage.trim() && isReady
                        ? 'preset-filled-primary-500'
                        : 'preset-tonal'}"
                >
                    {#if isSending}
                        <Loader size={18} class="animate-spin" />
                    {:else}
                        <SendHorizonal size={18} />
                    {/if}
                </button>
            </div>
        </div>
    </section>
</div>