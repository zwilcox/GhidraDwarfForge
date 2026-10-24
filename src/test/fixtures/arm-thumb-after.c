/* Link this ARM unit after the Thumb unit: the mode cue must end at this entry. */
__attribute__((noinline)) int arm_after(int value)
{
    return value + 5;
}
