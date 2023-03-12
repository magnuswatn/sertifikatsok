<script>
    export let error;

    import ErrorMessage from "./messages/ErrorMessage.svelte";
    import { getErrorText } from "./utils";
</script>

<ErrorMessage message={getErrorText(error)} />
