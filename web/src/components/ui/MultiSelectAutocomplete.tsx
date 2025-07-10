import { Autocomplete, AutocompleteItem, Button, Chip } from '@heroui/react'
import { useCallback, useEffect, useRef, useState } from 'react'

import LocalIcon from '../LocalIcon';

export interface MultiSelectAutocompleteProps {
  items: string[]
  label: string
  selectedItems?: string[]
  onSelectionChange?: (items: string[]) => void
  allowCustomValues?: boolean
  className?: string
  maxVisibleItems?: number
}

interface AutocompleteItemData {
  value: string
  label: string
}

/**
 * A reusable multi-select autocomplete component that supports custom values and chip display
 */
export function MultiSelectAutocomplete({
  items: defaultItems,
  label,
  selectedItems: externalSelectedItems,
  onSelectionChange,
  className,
  maxVisibleItems,
}: MultiSelectAutocompleteProps) {
  // Use props directly instead of useState to always get latest data
  const items = defaultItems
  const [selectedItems, setSelectedItems] = useState<string[]>(externalSelectedItems || [])
  const [inputValue, setInputValue] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const selectedItemsRef = useRef(selectedItems)

  const handleSelectItem = (item: string) => {
    if (!item) return
    const newSelectedItems = !selectedItems.includes(item)
      ? [...selectedItems, item]
      : selectedItems.filter((f) => f !== item)

    setSelectedItems(newSelectedItems)
    onSelectionChange?.(newSelectedItems)
    setInputValue('')
  }

  const handleRemoveItem = (item: string) => {
    const newSelectedItems = selectedItems.filter(
      (selectedItem) => selectedItem !== item,
    )
    setSelectedItems(newSelectedItems)
    onSelectionChange?.(newSelectedItems)
  }

  const filteredItems: AutocompleteItemData[] = inputValue
    ? items
        .filter((item) =>
          item.toLowerCase().includes(inputValue.toLowerCase()),
        )
        .map((item) => ({ value: item, label: item }))
    : items.map((item) => ({ value: item, label: item }))

  // Manage the filled-within state for the label
  const changeFilledWithin = useCallback((filledWithin: string | null) => {
    const isFilledWithin = !!(filledWithin === 'true' || inputRef?.current?.getAttribute('data-filled-within') === 'true')
    const filled = isFilledWithin || selectedItemsRef.current.length
    const parentElement = inputRef?.current?.parentElement?.parentElement?.parentElement
    if (parentElement instanceof HTMLElement) {
      parentElement.setAttribute('data-filled-within', filled ? 'true' : 'false')
    }
  }, [])

  // Update internal state when external selectedItems change
  useEffect(() => {
    if (externalSelectedItems) {
      setSelectedItems(externalSelectedItems)
    }
  }, [externalSelectedItems])

  useEffect(() => {
    selectedItemsRef.current = selectedItems
    changeFilledWithin(null)
  }, [selectedItems, changeFilledWithin])

  useEffect(() => {
    const handleMutation = (mutationsList: MutationRecord[]) => {
      for (const mutation of mutationsList) {
        if (mutation.type === 'attributes' && mutation.attributeName === 'data-filled-within') {
          const target = mutation.target as HTMLElement
          changeFilledWithin(target.getAttribute('data-filled-within'))
        }
      }
    }

    if (inputRef.current) {
      const observer = new MutationObserver(handleMutation)
      observer.observe(inputRef.current, { attributes: true })
      return () => observer.disconnect()
    }
  }, [changeFilledWithin])

  return (
    <div role="presentation" tabIndex={-1}>
      <Autocomplete
        ref={inputRef}
        items={filteredItems}
        label={label}
        className={className}
        menuTrigger="focus"
        classNames={{
          base: 'overflow-hidden',
          endContentWrapper: 'absolute top-[0.4px] right-3',
        }}
        startContent={
          <div className="flex flex-wrap gap-1">
            {(maxVisibleItems ? selectedItems.slice(0, maxVisibleItems) : selectedItems).map((item) => (
              <Chip
                key={item}
                variant="flat"
                className="bg-default-100 dark:bg-default-50 rounded-lg min-w-0"
                endContent={
                  <LocalIcon icon="lucide:x"
                    className="rounded-full hover:bg-default/40 p-1 cursor-pointer size-5 mr-1"
                    onClick={() => handleRemoveItem(item)}
                  />
                }
              >
                {item}
              </Chip>
            ))}
            {maxVisibleItems && selectedItems.length > maxVisibleItems && (
              <Chip
                variant="flat"
                className="bg-default-200 dark:bg-default-100 rounded-lg"
              >
                +{selectedItems.length - maxVisibleItems} more
              </Chip>
            )}
          </div>
        }
        endContent={
          selectedItems.length > 0 && (
            <Button
              variant="light"
              isIconOnly
              size="sm"
              className="rounded-full opacity-0 group-data-[hover=true]:opacity-100 data-[hover=true]:bg-default/40"
              onPress={() => {
                setSelectedItems([])
                onSelectionChange?.([])
              }}
            >
              <LocalIcon icon="lucide:x" className="size-4" />
            </Button>
          )
        }
        onSelectionChange={(key) => {
          if (key && typeof key === 'string') {
            handleSelectItem(key)
          }
        }}
        selectedKey={''}
        inputValue={inputValue}
        onInputChange={setInputValue}
        listboxProps={{
          emptyContent: items.length === 0 ? 'No options available' : 'No results found'
        }}
        inputProps={{
          classNames: {
            label: 'mt-2.5 group-data-[filled-within=true]:translate-y-0 group-data-[filled-within=true]:mt-0',
            inputWrapper: `block ${selectedItems.length === 0 ? 'min-h-8' : 'h-auto'}`,
            innerWrapper: `flex flex-wrap gap-1 h-auto ${
              selectedItems.length === 0 ? 'mt-3 -ml-1.5' : 'mt-6'
            }`,
            input: 'min-w-56 w-full h-7',
          },
        }}
      >
        {(item) => (
          <AutocompleteItem
            key={item.value}
            textValue={item.label}
            endContent={
              selectedItems.includes(item.value) && (
                <LocalIcon icon="lucide:check" className="size-4" />
              )
            }
          >
            {item.label}
          </AutocompleteItem>
        )}
      </Autocomplete>
    </div>
  )
}